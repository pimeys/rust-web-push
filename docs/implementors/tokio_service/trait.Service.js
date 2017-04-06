(function() {var implementors = {};
implementors["hyper_tls"] = ["impl <a class='trait' href='tokio_service/trait.Service.html' title='tokio_service::Service'>Service</a> for <a class='struct' href='hyper_tls/struct.HttpsConnector.html' title='hyper_tls::HttpsConnector'>HttpsConnector</a>",];
implementors["tokio_proto"] = ["impl&lt;T, P&gt; <a class='trait' href='tokio_service/trait.Service.html' title='tokio_service::Service'>Service</a> for <a class='struct' href='tokio_proto/pipeline/struct.ClientService.html' title='tokio_proto::pipeline::ClientService'>ClientService</a>&lt;T, P&gt; <span class='where fmt-newline'>where T: 'static, P: <a class='trait' href='tokio_proto/pipeline/trait.ClientProto.html' title='tokio_proto::pipeline::ClientProto'>ClientProto</a>&lt;T&gt;</span>","impl&lt;T, P&gt; <a class='trait' href='tokio_service/trait.Service.html' title='tokio_service::Service'>Service</a> for <a class='struct' href='tokio_proto/multiplex/struct.ClientService.html' title='tokio_proto::multiplex::ClientService'>ClientService</a>&lt;T, P&gt; <span class='where fmt-newline'>where T: 'static, P: <a class='trait' href='tokio_proto/multiplex/trait.ClientProto.html' title='tokio_proto::multiplex::ClientProto'>ClientProto</a>&lt;T&gt;</span>","impl&lt;R, S, E:&nbsp;<a class='trait' href='https://doc.rust-lang.org/nightly/core/convert/trait.From.html' title='core::convert::From'>From</a>&lt;<a class='struct' href='https://doc.rust-lang.org/nightly/std/io/error/struct.Error.html' title='std::io::error::Error'>Error</a>&gt;&gt; <a class='trait' href='tokio_service/trait.Service.html' title='tokio_service::Service'>Service</a> for <a class='struct' href='tokio_proto/util/client_proxy/struct.ClientProxy.html' title='tokio_proto::util::client_proxy::ClientProxy'>ClientProxy</a>&lt;R, S, E&gt;",];
implementors["tokio_service"] = [];
implementors["web_push"] = ["impl <a class='trait' href='tokio_service/trait.Service.html' title='tokio_service::Service'>Service</a> for <a class='struct' href='web_push/struct.WebPushClient.html' title='web_push::WebPushClient'>WebPushClient</a>",];

            if (window.register_implementors) {
                window.register_implementors(implementors);
            } else {
                window.pending_implementors = implementors;
            }
        
})()
