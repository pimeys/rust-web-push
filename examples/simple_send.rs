use serde_json;
use tokio;
use web_push::*;
use futures::{future::lazy, Future};

use argparse::{
    ArgumentParser,
    Store,
    StoreOption
};

use std::{
    fs::File,
    io::Read,
    time::Duration,
};

fn main() {
    let mut subscription_info_file = String::new();
    let mut gcm_api_key: Option<String> = None;
    let mut vapid_private_key: Option<String> = None;
    let mut push_payload: Option<String> = None;
    let mut ttl: Option<u32> = None;

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("A web push sender");

        ap.refer(&mut gcm_api_key)
            .add_option(&["-k", "--gcm_api_key"], StoreOption, "Google GCM API Key");

        ap.refer(&mut vapid_private_key)
            .add_option(&["-v", "--vapid_key"], StoreOption,
                        "A NIST P256 EC private key to create a VAPID signature");

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

    let subscription_info: SubscriptionInfo = serde_json::from_str(&contents).unwrap();

    let mut builder = WebPushMessageBuilder::new(&subscription_info).unwrap();

    if let Some(ref payload) = push_payload {
        builder.set_payload(ContentEncoding::AesGcm, payload.as_bytes());
    }

    if let Some(ref gcm_key) = gcm_api_key {
        builder.set_gcm_key(gcm_key);
    }

    if let Some(time) = ttl {
        builder.set_ttl(time);
    }

    if let Some(ref vapid_file) = vapid_private_key {
        let file = File::open(vapid_file).unwrap();

        let mut sig_builder = VapidSignatureBuilder::from_pem(file, &subscription_info).unwrap();

        sig_builder.add_claim("sub", "mailto:test@example.com");
        sig_builder.add_claim("foo", "bar");
        sig_builder.add_claim("omg", 123);

        let signature = sig_builder.build().unwrap();

        builder.set_vapid_signature(signature);
    };

    match builder.build() {
        Ok(message) => {
            let client = WebPushClient::new().unwrap();

            tokio::run(lazy(move || {
                client
                    .send_with_timeout(message, Duration::from_secs(4))
                    .map(|response| {
                        println!("Sent: {:?}", response);
                    }).map_err(|error| {
                        println!("Error: {:?}", error)
                    })
            }));
        },
        Err(error) => {
            println!("ERROR in building message: {:?}", error)
        }
    }
}
