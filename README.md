Rust Web Push
=============

[![Cargo tests](https://github.com/pimeys/rust-web-push/actions/workflows/test.yml/badge.svg)](https://github.com/pimeys/rust-web-push/actions/workflows/test.yml)
[![crates.io](https://img.shields.io/crates/d/web-push)](https://crates.io/crates/web_push)
[![docs.rs](https://docs.rs/web-push/badge.svg)](https://docs.rs/web-push)

[Matrix chat](https://matrix.to/#/#rust-push:nauk.io?via=nauk.io&via=matrix.org&via=shine.horse)

Web push notification sender.

## Requirements

Any async executor for use with client.

## Migration to v0.8

- The `aesgcm` variant of `ContentEncoding` has been removed. Aes128Gcm support was added in v0.8, so all uses
  of `ContentEncoding::aesgcm` can simply be changed to `ContentEncoding::Aes128Gcm` with no change to functionality.
  This will add support for Edge in the process.

- `WebPushClient::new()` now returns a `Result`, as the default client now has a fallible constructor. Please handle
  this error in the case of resource starvation.

- All GCM/FCM support has been removed. If you relied on this functionality, consider
  the [fcm crate](https://crates.io/crates/fcm). If you just require web push, you will need to use VAPID to send
  payloads. See below for info.

## Usage

To send a web push from command line, first subscribe to receive push notifications with your browser and store the
subscription info into a json file. It should have the following content:

``` json
{
  "endpoint": "https://updates.push.services.mozilla.com/wpush/v1/TOKEN",
  "keys": {
    "auth": "####secret####",
    "p256dh": "####public_key####"
  }
}
```

Google has
[good instructions](https://developers.google.com/web/fundamentals/push-notifications/subscribing-a-user) for building a
frontend to receive notifications.

Store the subscription info to `examples/test.json` and send a notification with
`cargo run --example simple_send -- -f examples/test.json -p "It works!"`.

Example
--------

```rust
use web_push::*;
use base64::URL_SAFE;
use std::fs::File;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let endpoint = "https://updates.push.services.mozilla.com/wpush/v1/...";
    let p256dh = "key_from_browser_as_base64";
    let auth = "auth_from_browser_as_base64";

    //You would likely get this by deserializing a browser `pushSubscription` object.  
    let subscription_info = SubscriptionInfo::new(
        endpoint,
        p256dh,
        auth
    );

    //Read signing material for payload.
    let file = File::open("private.pem").unwrap();
    let mut sig_builder = VapidSignatureBuilder::from_pem(file, &subscription_info)?.build()?;

    //Now add payload and encrypt.
    let mut builder = WebPushMessageBuilder::new(&subscription_info)?;
    let content = "Encrypted payload to be sent in the notification".as_bytes();
    builder.set_payload(ContentEncoding::Aes128Gcm, content);
    builder.set_vapid_signature(sig_builder);

    let client = WebPushClient::new()?;

    //Finally, send the notification!
    client.send(builder.build()?).await?;
    Ok(())
}
 ```

VAPID
-----

VAPID authentication prevents unknown sources sending notifications to the client and is required by all current
browsers when sending a payload.

The private key to be used by the server can be generated with OpenSSL:

```
openssl ecparam -genkey -name prime256v1 -out private_key.pem
```

To derive a public key from the just-generated private key, to be used in the JavaScript client:

```
openssl ec -in private_key.pem -pubout -outform DER|tail -c 65|base64|tr '/+' '_-'|tr -d '\n'
```

The signature is created with `VapidSignatureBuilder`. It automatically adds the required claims `aud` and `exp`. Adding
these claims to the builder manually will override the default values.

Overview
--------

Currently, implements
[RFC8188](https://datatracker.ietf.org/doc/html/rfc8188) content encryption for notification payloads. This is done by
delegating encryption to mozilla's [ece crate](https://crates.io/crates/ece). Our security is thus tied
to [theirs](https://github.com/mozilla/rust-ece/issues/18). The default client is built
on [isahc](https://crates.io/crates/isahc), but can be swapped out with a hyper based client using the
`hyper-client` feature. Custom clients can be made using the `request_builder` module.

Library tested with Google's and Mozilla's push notification services. Also verified to work on Edge.

Debugging
--------
If you get an error or the push notification doesn't work you can try to debug using the following instructions:

Add the following to your Cargo.toml:

```cargo
log = "0.4"
pretty_env_logger = "0.3"
```

Add the following to your main.rs:

```rust
extern crate pretty_env_logger;

// ...
fn main() {
    pretty_env_logger::init();
    // ...
}
```

Or use any other logging library compatible with https://docs.rs/log/

Then run your program with the following environment variables:

```bash
RUST_LOG="web_push::client=trace" cargo run
```

This should print some more information about the requests to the push service which may aid you or somebody else in
finding the error.
