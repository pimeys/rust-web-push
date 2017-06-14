Rust Web Push
=============

[![Travis Build Status](https://travis-ci.org/pimeys/rust-web-push.svg?branch=master)](https://travis-ci.org/pimeys/rust-web-push)

Web push notification sender.

Documentation
-------------

* [Master](https://pimeys.github.io/rust-web-push/web_push/index.html)

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
`cargo run --example simple_send -- -f examples/test.json -p "It works!"`. If
using Google Chrome, you need to register yourself
into [Firebase](https://firebase.google.com/) and provide a GCM API Key with
parameter `-k GCM_API_KEY`.

Overview
--------

Currently implements
[HTTP-ECE Draft-3](https://datatracker.ietf.org/doc/draft-ietf-httpbis-encryption-encoding/03/?include_text=1)
content encryption for notification payloads. The client requires
[Tokio](https://tokio.rs) for asynchronious requests. The modular design allows
an easy extension for the upcoming aes128gcm when the browsers are getting
support for it.

Tested with Google's and Mozilla's push notification services.
