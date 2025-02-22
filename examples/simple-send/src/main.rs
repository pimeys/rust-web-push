use std::{fs::File, io::Read};

use argparse::{ArgumentParser, Store, StoreOption};
use web_push::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let mut subscription_info_file = String::new();
    let mut vapid_private_key: Option<String> = None;
    let mut push_payload: Option<String> = None;
    let mut encoding: Option<String> = None;
    let mut ttl: Option<u32> = None;

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("A web push sender");

        ap.refer(&mut vapid_private_key).add_option(
            &["-v", "--vapid_key"],
            StoreOption,
            "A NIST P256 EC private key to create a VAPID signature",
        );

        ap.refer(&mut encoding).add_option(
            &["-e", "--encoding"],
            StoreOption,
            "Content Encoding Scheme : 'aes128gcm' or 'aesgcm'",
        );

        ap.refer(&mut subscription_info_file).add_option(
            &["-f", "--subscription_info_file"],
            Store,
            "Subscription info JSON file, https://developers.google.com/web/updates/2016/03/web-push-encryption",
        );

        ap.refer(&mut push_payload)
            .add_option(&["-p", "--push_payload"], StoreOption, "Push notification content");

        ap.refer(&mut ttl)
            .add_option(&["-t", "--time_to_live"], StoreOption, "TTL of the notification");

        ap.parse_args_or_exit();
    }

    let mut file = File::open(subscription_info_file).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    let ece_scheme = match encoding.as_deref() {
        Some("aes128gcm") => ContentEncoding::Aes128Gcm,
        Some("aesgcm") => ContentEncoding::AesGcm,
        None => ContentEncoding::Aes128Gcm,
        Some(_) => panic!("Content encoding can only be 'aes128gcm' or 'aesgcm'"),
    };

    let subscription_info: SubscriptionInfo = serde_json::from_str(&contents).unwrap();

    let mut builder = WebPushMessageBuilder::new(&subscription_info);

    if let Some(ref payload) = push_payload {
        builder.set_payload(ece_scheme, payload.as_bytes());
    } else {
        builder.set_payload(ece_scheme, "Hello world!".as_bytes());
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

    let client = IsahcWebPushClient::new()?;

    let result = client.send(builder.build()?).await;

    if let Err(error) = result {
        println!("An error occured: {:?}", error);
    }

    Ok(())
}
