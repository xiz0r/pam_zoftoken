#[macro_use]
extern crate pam;
extern crate reqwest;
extern crate serde;
extern crate syslog;

use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};
use reqwest::{Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::ffi::CStr;
use syslog::{Facility, Formatter3164};

#[derive(Deserialize)]
struct ZoftokenResponse {
    status: i32,
}

macro_rules! pam_try {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return e,
        }
    };
    ($e:expr, $err:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => {
                logger(format!("Error: {}", e), true);
                return $err;
            }
        }
    };
}

struct PamHttp;
pam_hooks!(PamHttp);

impl PamHooks for PamHttp {
    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {

        let args: Vec<_> = args
            .iter()
            .map(|s| s.to_string_lossy().to_owned())
            .collect();
        let args: HashMap<&str, &str> = args
            .iter()
            .map(|s| {
                let mut parts = s.splitn(2, "=");
                (parts.next().unwrap(), parts.next().unwrap_or(""))
            })
            .collect();

        let user = pam_try!(pamh.get_user(None));
        let is_debug = args.get("debug").unwrap_or(&"false").parse::<bool>().unwrap();

        let service: &str = match args.get("service") {
            Some(service) => service,
            None => return PamResultCode::PAM_AUTH_ERR,
        };
        let auth_key = match args.get("auth_key") {
            Some(auth_key) => auth_key,
            None => return PamResultCode::PAM_AUTH_ERR,
        };
        let host = match args.get("host") {
            Some(host) => host,
            None => return PamResultCode::PAM_AUTH_ERR,
        };
        let no_2fa_user = match args.get("no_2fa_user") {
            Some(no_2fa_user) => no_2fa_user,
            None => "",
        };

        if no_2fa_user == &user {
            logger(format!(
                "[zoftoken]: no_2fa_user logged in: {}",
                no_2fa_user
            ), is_debug);
            return PamResultCode::PAM_IGNORE;
        }
        
        let url = format!(
            "https://{host}/token/status?id={user}&service={service}&authKey={authkey}",
            host = host,
            user = user,
            service = service,
            authkey = auth_key
        );

        logger(format!("[zoftoken]: url: {}", url), is_debug);

        let result = pam_try!(get_url(&url), PamResultCode::PAM_AUTH_ERR);

        if result.status == 1 {
            logger(String::from("[zoftoken]: OK"), is_debug);
            return PamResultCode::PAM_SUCCESS;
        }

        logger(String::from("[zoftoken]: Error token closed"), is_debug);
        PamResultCode::PAM_AUTH_ERR
    }

    fn sm_setcred(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }
}

fn get_url(url: &str) -> Result<ZoftokenResponse> {
    let result = reqwest::blocking::get(url)?.json::<ZoftokenResponse>()?;
    Ok(result)
}

fn logger(msg: String, is_debug: bool) {
    if !is_debug {
        return
    }

    let formatter = Formatter3164 {
        facility: Facility::LOG_AUTH,
        hostname: None,
        process: "pam_zoftoken".into(),
        pid: 42,
    };
    match syslog::unix(formatter) {
        Err(e) => println!("impossible to connect to syslog: {:?}", e),
        Ok(mut writer) => writer
            .info(msg)
            .expect("could not write pam_zoftoken message"),
    }
}
