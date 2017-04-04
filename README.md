Rust Web Push
=============

Web Push sender. Works with
[HTTP-ECE Draft-3](https://datatracker.ietf.org/doc/draft-ietf-httpbis-encryption-encoding/03/?include_text=1)

Sending a notification:
-----------------------

``` rust
extern crate web_push;
extern crate rustc_serialize;
extern crate tokio_core;

use rustc_serialize::base64::FromBase64;
use web_push::{WebPushMessageBuilder, WebPushClient};

fn main() {
    # These three values come from the browser when user subscribes to get notifications:
    let endpoint = "http://some.endpoint/web_token";
    let p256dh = "XXXYYY".from_base64().unwrap();
    let auth = "ZZZLLL".from_base64().unwrap();

    let mut builder = WebPushMessageBuilder::new(endpoint, &auth, &p256dh);
    builder.set_payload("This is test data.".as_bytes());

    match builder.build() {
        Ok(message) => {
            let mut core = tokio_core::reactor::Core::new().unwrap();
            let handle = core.handle();
            let client = WebPushClient::new(&handle);

            let work = client.send(message);

            match core.run(work) {
                Err(error) => println!("ERROR: {:?}", error),
                _ => println!("SENT")
            }
        },
        Err(error) => {
            println!("ERROR in building message: {:?}", error)
        }
    }
}
```

When sending to Google's API, one must register to
[Firebase](https://firebase.google.com/) and include a `gcm_api_key` with the
notification:

``` rust

```
