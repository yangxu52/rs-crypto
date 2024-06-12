use sha2::{Digest, Sha256, Sha512};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct SHA2 {}
/// SHA2 Digest Module
#[wasm_bindgen]
impl SHA2 {
    /// SHA2 224
    #[wasm_bindgen]
    pub fn sha224(plain_text: &str) -> String {
        let mut hash_instance = sha2::Sha224::new();
        hash_instance.update(plain_text.as_bytes());
        let hash = hash_instance.finalize();
        format!("{:x}", hash)
    }
    /// SHA2 256
    #[wasm_bindgen]
    pub fn sha256(plain_text: &str) -> String {
        let mut hash_instance = Sha256::new();
        hash_instance.update(plain_text.as_bytes());
        let hash = hash_instance.finalize();
        format!("{:x}", hash)
    }
    /// SHA2 384
    #[wasm_bindgen]
    pub fn sha384(plain_text: &str) -> String {
        let mut hash_instance = sha2::Sha384::new();
        hash_instance.update(plain_text.as_bytes());
        let hash = hash_instance.finalize();
        format!("{:x}", hash)
    }
    /// SHA2 512
    #[wasm_bindgen]
    pub fn sha512(plain_text: &str) -> String {
        let mut hash_instance = Sha512::new();
        hash_instance.update(plain_text.as_bytes());
        let hash = hash_instance.finalize();
        format!("{:x}", hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sha2() {
        let plain_text = "Hello, World!";
        let sha2_224 = SHA2::sha224(plain_text);
        let sha2_256 = SHA2::sha256(plain_text);
        let sha2_384 = SHA2::sha384(plain_text);
        let sha2_512 = SHA2::sha512(plain_text);
        assert_eq!(
            sha2_224,
            "72a23dfa411ba6fde01dbfabf3b00a709c93ebf273dc29e2d8b261ff"
        );
        assert_eq!(
            sha2_256,
            "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        );
        assert_eq!(
            sha2_384,
            "5485cc9b3365b4305dfb4e8337e0a598a574f8242bf17289e0dd6c20a3cd44a089de16ab4ab308f63e44b1170eb5f515"
        );
        assert_eq!(
            sha2_512,
            "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387"
        );
    }
}
