extern crate web_push;
extern crate rustc_serialize;
extern crate tokio_core;
extern crate argparse;

use rustc_serialize::json;
use rustc_serialize::base64::FromBase64;
use web_push::{WebPushMessageBuilder, WebPushClient};
use argparse::{ArgumentParser, Store, StoreOption};
use std::fs::File;
use std::io::Read;

#[derive(RustcDecodable, RustcEncodable)]
struct SubscriptionKeys {
    p256dh: String,
    auth: String,
}

#[derive(RustcDecodable, RustcEncodable)]
struct SubscriptionInfo {
    endpoint: String,
    keys: SubscriptionKeys,
}

fn main() {
    let mut subscription_info_file = String::new();
    let mut gcm_api_key: Option<String> = None;
    let mut push_payload: Option<String> = None;
    let mut ttl: Option<u32> = None;

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("A web push sender");

        ap.refer(&mut gcm_api_key)
            .add_option(&["-k", "--gcm_api_key"], StoreOption, "Google GCM API Key");

        ap.refer(&mut subscription_info_file)
            .add_option(&["-f", "--subscription_info_file"], Store,
                        "Subscription info JSON file, https://developers.google.com/web/updates/2016/03/web-push-encryption");

        ap.refer(&mut push_payload)
            .add_option(&["-p", "--push_payload"], StoreOption, "Push notification content");

        ap.refer(&mut ttl)
            .add_option(&["-t", "--time_to_live"], StoreOption, "TTL of the notification");

        ap.parse_args_or_exit();
    }

    let mut file = File::open(subscription_info_file).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    let subscription_info: SubscriptionInfo = json::decode(&contents).unwrap();

    let auth = subscription_info.keys.auth.from_base64().unwrap();
    let p256dh = subscription_info.keys.p256dh.from_base64().unwrap();

    let mut builder = WebPushMessageBuilder::new(&subscription_info.endpoint, &auth, &p256dh);

    if let Some(ref payload) = push_payload {
        builder.set_payload(payload.as_bytes());
    }

    if let Some(ref gcm_key) = gcm_api_key {
        builder.set_gcm_key(gcm_key);
    }

    match builder.build() {
        Ok(message) => {
            let mut core = tokio_core::reactor::Core::new().unwrap();
            let handle = core.handle();
            let client = WebPushClient::new(&handle);

            let work = client.send(message);

            match core.run(work) {
                Err(error) => println!("ERROR: {:?}", error),
                _ => println!("OK")
            }
        },
        Err(error) => {
            println!("ERROR in building message: {:?}", error)
        }
    }
}
