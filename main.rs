#[macro_use] extern crate serde_derive;

use clap::clap_app;
use url::Url;
use restson::{ RestPath, RestClient };
use restson::Error as RError;
use http::method::Method;
use std::collections::{ HashSet, HashMap };
use std::time::{ UNIX_EPOCH, SystemTime };
use failure::{ Fallible, bail };

#[derive(Serialize,Deserialize,Debug,Clone)]
#[serde(tag = "type")]
enum Identifier {
	#[serde(rename="m.id.user")] User{user: String},
	#[serde(rename="m.id.thirdparty")] Thirdparty{medium: String, address: String},
	#[serde(rename="m.id.phone")] Phone{country: String, phone: String},
}
#[derive(Serialize,Deserialize,Debug,Clone)]
#[serde(tag = "type")]
enum LoginReq {
	#[serde(rename="m.login.password")]
	Password {
		identifier: Identifier,
		password: String,
		#[serde(default)]
		initial_device_display_name: String,
		session: Option<String>,
	},
	// m.login.recaptcha, m.login.oauth2, m.login.email.identity, m.login.token, m.login.dummy
	// not supported
}
#[derive(Serialize,Deserialize,Debug,Clone)]
struct LoginResp {
	user_id: String,
	access_token: String,
	device_id: String,
}
#[derive(Serialize,Deserialize,Debug,Clone)]
struct DeviceInfo {
	// There's a user_id field, but…
	device_id: String,
	display_name: Option<String>,
	last_seen_ip: Option<String>,
	#[serde(with = "serde_millis")]
	last_seen_ts: Option<SystemTime>,
}
#[derive(Serialize,Deserialize,Debug,Clone)]
struct DeviceList {
	devices: Vec<DeviceInfo>
}
#[derive(Serialize,Deserialize,Debug,Clone)]
struct InteractiveAuthReq {
	session: String,
	#[serde(default)]
	flows: Vec<HashMap<String, Vec<String>>>,
	// I no support params
}
#[derive(Serialize,Deserialize,Debug,Clone)]
#[serde(tag = "type")]
enum InteractiveAuthResp {
	// Only password supported, so I'm just moving session and user into there…
	#[serde(rename="m.login.password")]
	Password {
		session: String,
		password: String,
		user: String,
	}
}
#[derive(Serialize,Deserialize,Debug,Clone)]
struct DeleteDevReq {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	auth: Option<InteractiveAuthResp>,
}

impl RestPath<()> for LoginReq {
	fn get_path(_: ()) -> Result<String,RError> { Ok(String::from("/_matrix/client/r0/login")) }
}
impl RestPath<()> for DeviceList {
	fn get_path(_: ()) -> Result<String,RError> { Ok(String::from("/_matrix/client/r0/devices")) }
}
struct DeleteDevice {}
impl RestPath<&str> for DeleteDevice {
	fn get_path(id: &str) -> Result<String,RError> { Ok(format!("/_matrix/client/r0/devices/{}", id)) }
}

const OWNNAME: &str = "Device Cleaning Device";

struct Deleter {
	client: RestClient,
	user: String,
	pass: String,
	devices: Option<Vec<DeviceInfo>>,
	ownid: Option<String>,
}
impl Drop for Deleter {
	fn drop(&mut self) {
		let ownid = self.ownid.take();
		ownid.map(|id| {
			match self.delete(&id) {
				Err(_err) => { eprintln!("Failed to clean up own device. (Sorry. This is the opposite of what you wanted.)"); }
				Ok(()) => {},
			}
		});
	}
}
impl Deleter {
	fn new(remote: &str, user: String, pass: String) -> Fallible<Deleter> {
		let client = RestClient::new(remote)?;
		Ok(Deleter { client, user, pass, devices: None, ownid: None })
	}

	fn login_req(&self, session: Option<String>) -> LoginReq {
		LoginReq::Password {
			identifier: Identifier::User { user: self.user.clone() },
			password: self.pass.clone(),
			initial_device_display_name: String::from(OWNNAME),
			session,
		}
	}

	fn login(&mut self) -> Fallible<()> {
		let auth: LoginResp = self.client.post_capture((), &self.login_req(None))?;
		let LoginResp { device_id, user_id, access_token } = auth;
		println!("Authenticated as {}.", user_id);
		self.client.set_header("Authorization", &format!("Bearer {}", access_token))?;
		self.ownid = Some(device_id);
		self.user = user_id;
		Ok(())
	}

	fn device_list(&mut self) -> Fallible<&Vec<DeviceInfo>> {
		if self.devices.is_none() {
			let dl: DeviceList = self.client.get(())?;
			self.devices = Some(dl.devices.into_iter().map(|d| DeviceInfo { last_seen_ip: d.last_seen_ip.filter(|x| x.to_string() != "-".to_string()), ..d }).collect());
		}
		Ok(self.devices.as_ref().unwrap())
	}
	fn delete(&mut self, id: &str) -> Fallible<()> {
		if Some(id) == self.ownid.as_ref().map(String::as_str) {
			return Ok(()) // If we delete ourselves before the drop, we'll run into errors.
		}
		println!("Deleting {}...", id);
		self.delete_with_data(id, None, 3)
	}
	fn delete_with_data(&mut self, id: &str, auth: Option<InteractiveAuthResp>, attempts: usize) -> Fallible<()> {
		if attempts == 0 {
			bail!("Out of attempts for deleting {}.", id);
		}
		let body = serde_json::to_string(&DeleteDevReq { auth })?;
		let req = self.client.make_request::<&str, DeleteDevice>(Method::DELETE, id, None, Some(body))?;
		match self.client.run_request(req) {
			Err(RError::HttpError(401, ref content)) => {
				let InteractiveAuthReq { session, flows } = serde_json::from_str(&content)?;
				for flow in flows {
					if flow.get("stages") == Some(&vec![String::from("m.login.password")]) {
						//println!("Reauthenticating in delete session {}...", session);
						let auth = InteractiveAuthResp::Password {
							session,
							password: self.pass.clone(),
							user: self.user.clone(),
						};
						return self.delete_with_data(id, Some(auth), attempts - 1);
					}
				}
				bail!("Server does not support password auth. (How did you even manage to log in?)");
			},
			any => { any?; Ok(()) }
		}
	}
}
fn main() -> Fallible<()> {
	let params = clap_app!(devclean =>
		(version: "0.1")
		(author: "Julius Michaelis <mdcs@liftm.de>")
		(about: "List and delete orphaned devices on a matrix homeserver")
		(@setting SubcommandRequiredElseHelp)
		(@arg homeserver: -h --homeserver --url +takes_value +required "URL of Homeserver")
		(@arg user: -u --user --id +takes_value +required "User ID (phone number and external auth not supported)")
		(@subcommand list => 
			(about: "Lists device IDs and information")
		)
		(@subcommand delete => 
			(about: "Delete Devices (TBI)")
			(@arg expire: -e --expire +takes_value  "Delete all devices older than X (e.g. \"30days\")")
			(@arg clean: -c --clean  "Cleanup insane devices (No display name, strange date value)")
			(@arg ids: -i --ids "List of IDs to remove")
		)
	).get_matches();
	let hs = Url::parse(params.value_of("homeserver").expect("homeserver url"))?;
	let user = String::from(params.value_of("user").expect("user"));
	let pass = rpassword::read_password_from_tty(Some(&format!("Password for @{}:{}: ", user, hs.host_str().expect("Host name in homeserver URL")))).unwrap();
	let mut app = Deleter::new(hs.as_str(), user, pass)?;
	app.login()?;

	match params.subcommand() {
		("list", _) => {
			for dev in app.device_list()? {
				println!("Device: {}, ID: {}{}{}", 
					dev.display_name.as_ref().unwrap_or(&"???".to_string()),
					dev.device_id,
					dev.last_seen_ip.as_ref().map(|ls| format!(", Last IP: {}", ls)).unwrap_or(String::from("")),
					dev.last_seen_ts.as_ref().map(|ls| format!(", Last seen: {}", humantime::format_rfc3339(*ls))).unwrap_or(String::from("")),
				);
			}
		},
		("delete", Some(subpars)) => {
			let mut del: HashSet<String> = HashSet::new();
			subpars.value_of("ids").map(|ids| ids.split(",").map(|id| del.insert(id.trim().to_string())));
			for d in subpars.value_of("expire") {
				let dur = d.parse::<humantime::Duration>().expect("Parsing expiration duration").into();
				let deltil = SystemTime::now() - dur;
				for dev in app.device_list()?.iter() {
					if dev.last_seen_ts.map(|ls| ls < deltil).unwrap_or(false) {
						del.insert(dev.device_id.clone());
					}
				}
			}
			if subpars.is_present("clean") {
				for dev in app.device_list()?.iter() {
					if dev.display_name.is_none() 
					|| dev.display_name == Some(OWNNAME.to_string()) 
					|| dev.last_seen_ts.is_none()
					|| dev.last_seen_ts == Some(UNIX_EPOCH) 
					{
						del.insert(dev.device_id.clone());
					}
				}
			}
			for d in del {
				app.delete(&d)?;
			}
		},
		_ => unreachable!(),
	}

	Ok(())
}
