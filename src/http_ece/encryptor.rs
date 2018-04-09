use error::WebPushError;

pub trait Encryptor<'a> {
    fn encrypt(&self, payload: &'a mut [u8]) -> Result<(), WebPushError>;
    fn headers(&self) -> Vec<(&'static str, String)>;
    fn pad(payload: &'a [u8], padded_output: &'a mut [u8]);
}
