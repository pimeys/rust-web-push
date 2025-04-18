use serde::Serialize;

/// Declarative notification that can be used to populate the payload of a web push.
///
/// See https://webkit.org/blog/16535/meet-declarative-web-push
#[derive(Debug, Serialize)]
pub struct Notification<D: Serialize> {
    pub title: String,
    pub navigate: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub badge: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub vibrate: Option<Vec<u32>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub renotify: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub silent: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "requireInteraction")]
    pub require_interaction: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<D>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<NotificationAction>>,
}

#[derive(Debug, Serialize)]
pub struct NotificationAction {
    pub title: String,
    pub action: String,
    pub navigate: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

impl<D: Serialize> Notification<D> {
    pub fn new(title: String, navigate: String) -> Self {
        Notification {
            title,
            navigate,
            lang: None,
            dir: None,
            tag: None,
            body: None,
            icon: None,
            image: None,
            badge: None,
            vibrate: None,
            timestamp: None,
            renotify: None,
            silent: None,
            require_interaction: None,
            data: None,
            actions: None,
        }
    }

    pub fn to_payload(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(&DeclarativePushPayload::new(self))
    }
}

#[derive(Debug, Serialize)]
struct DeclarativePushPayload<'a, D: Serialize> {
    web_push: u16,
    pub notification: &'a Notification<D>,
}

impl<'a, D: Serialize> DeclarativePushPayload<'a, D> {
    pub fn new(notification: &'a Notification<D>) -> Self {
        DeclarativePushPayload {
            web_push: 8030,
            notification,
        }
    }
}
