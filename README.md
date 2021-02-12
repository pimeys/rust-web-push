Rust Web Push
=============

![CI](https://github.com/pimeys/rust-web-push/workflows/CI/badge.svg)
[![crates.io](http://meritbadge.herokuapp.com/web_push)](https://crates.io/crates/web_push)
[![docs.rs](https://docs.rs/web-push/badge.svg)](https://docs.rs/web-push)

Web push notification sender.

## Runtime requirements

By default, compiles with the feature `rt-tokio` enabled, and should be used from Tokio 1.x runtime. Additionally, the feature `rt-async-std` allows using the crate with async-std 1.x runtime. Both flags cannot be enabled at the same time, so default features should be disabled if having the `rt-async-std` feature flag enabled.

Example Cargo.toml usage for Tokio:

``` toml
web-push = "0.8"
```

Example Cargo.toml usage for async-std:

``` toml
web-push = { version = "0.8", default-features = false, features = ["rt-async-std"] }
```

It is also possible to disable all features and BYO http client using `Request` and `Response` from the `http-types` crate:

``` toml
web-push = { version = "0.8", default-features = false }
```

You can then use `web_push::WebPushMessage::into` to obtain a `http_types::Request` and `web_push::read_reponse` to check the response.

Examples
--------

To send a web push from command line, first subscribe to receive push
notifications with your browser and store the subscription info into a json
file. It should have the following content:

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
[good instructions](https://developers.google.com/web/updates/2015/03/push-notifications-on-the-open-web) for
building a frontend to receive notifications.

Store the subscription info to `examples/test.json` and send a notification with
`cargo run --example simple_send -- -f examples/test.json -p "It works!"`.

Examples
--------

To see it used in a real project, take a look to the [XORC
Notifications](https://github.com/xray-tech/xorc-notifications), which is a
full-fledged consumer for sending push notifications.

VAPID
-----

VAPID authentication prevents unknown sources sending notifications to the
client and allows sending notifications to Chrome without signing in to Firebase
and providing a GCM API key.

The private key to be used by the server can be generated with OpenSSL:

```
openssl ecparam -genkey -name prime256v1 -out private_key.pem
```

To derive a public key from the just-generated private key, to be used in the
JavaScript client:

```
openssl ec -in private_key.pem -pubout -outform DER|tail -c 65|base64|tr '/+' '_-'|tr -d '\n'
```

The signature is created with `VapidSignatureBuilder`. It automatically adds the
required claims `aud` and `exp`. Adding these claims to the builder manually
will override the default values.

Overview
--------

Currently implements
[HTTP-ECE Draft-3](https://datatracker.ietf.org/doc/draft-ietf-httpbis-encryption-encoding/03/?include_text=1)
content encryption for notification payloads. The client requires
[Tokio](https://tokio.rs) for asynchronious requests. The modular design allows
an easy extension for the upcoming aes128gcm when the browsers are getting
support for it.

Tested with Google's and Mozilla's push notification services.

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

This should print some more information about the requests to the push service which may aid you or somebody else in finding the error.
