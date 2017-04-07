Rust Web Push
=============

[![Travis Build Status](https://travis-ci.org/pimeys/rust-web-push.svg?branch=master)](https://travis-ci.org/pimeys/rust-web-push)

Web push notification sender.

Documentation
-------------

* [Master](https://pimeys.github.io/rust-web-push/web_push/index.html)

Overview
--------

Waiting for Hyper 0.11 to be released, until that happens this crate will stay
out from crates.io (and might change a lot).

Currently implements
[HTTP-ECE Draft-3](https://datatracker.ietf.org/doc/draft-ietf-httpbis-encryption-encoding/03/?include_text=1)
content encryption for notification payloads. The client requires
[Tokio](https://tokio.rs) for asynchronious requests. The modular design allows
an easy extension for the upcoming aes128gcm when the browsers are getting
support for it.

Tested with Google's and Mozilla's push notification services.
