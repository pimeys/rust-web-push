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

#[cfg(test)]
mod tests {
    use serde::Serialize;
    use serde_json::Value;

    use super::{Notification, NotificationAction};

    fn parse_payload<D: Serialize>(notification: &Notification<D>) -> Value {
        let bytes = notification.to_payload().expect("to_payload should not fail");
        serde_json::from_slice(&bytes).expect("payload should be valid JSON")
    }

    #[test]
    fn test_new_sets_required_fields() {
        let n: Notification<()> = Notification::new("Hello".to_string(), "https://example.com/".to_string());
        assert_eq!(n.title, "Hello");
        assert_eq!(n.navigate, "https://example.com/");
    }

    #[test]
    fn test_payload_web_push_field_is_rfc8030_magic_value() {
        let n: Notification<()> = Notification::new("t".to_string(), "u".to_string());
        let v = parse_payload(&n);
        assert_eq!(v["web_push"], 8030);
    }

    #[test]
    fn test_require_interaction_serializes_as_camel_case() {
        let mut n: Notification<()> = Notification::new("t".to_string(), "u".to_string());
        n.require_interaction = Some(true);
        let v = parse_payload(&n);
        assert_eq!(v["notification"]["requireInteraction"], true);
        assert!(v["notification"].get("require_interaction").is_none());
    }

    #[test]
    fn test_payload_with_custom_data_struct() {
        #[derive(Serialize)]
        struct MyData {
            user_id: u32,
            action: String,
        }

        let mut n = Notification::new("t".to_string(), "u".to_string());
        n.data = Some(MyData {
            user_id: 42,
            action: "open".to_string(),
        });
        let v = parse_payload(&n);
        assert_eq!(v["notification"]["data"]["user_id"], 42);
        assert_eq!(v["notification"]["data"]["action"], "open");
    }

    #[test]
    fn test_payload_with_primitive_data() {
        let mut n = Notification::new("t".to_string(), "u".to_string());
        n.data = Some("just a string");
        let v = parse_payload(&n);
        assert_eq!(v["notification"]["data"], "just a string");
    }

    #[test]
    fn test_notification_actions() {
        let mut n: Notification<()> = Notification::new("t".to_string(), "u".to_string());
        n.actions = Some(vec![
            NotificationAction {
                title: "Accept".to_string(),
                action: "accept".to_string(),
                navigate: "https://example.com/accept".to_string(),
                icon: None,
            },
            NotificationAction {
                title: "Decline".to_string(),
                action: "decline".to_string(),
                navigate: "https://example.com/decline".to_string(),
                icon: Some("https://example.com/decline-icon.png".to_string()),
            },
        ]);
        let v = parse_payload(&n);
        let actions = v["notification"]["actions"].as_array().unwrap();
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0]["action"], "accept");
        assert!(actions[0].get("icon").is_none());
        assert_eq!(actions[1]["action"], "decline");
        assert_eq!(actions[1]["icon"], "https://example.com/decline-icon.png");
    }
}
