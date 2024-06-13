use core::panic;

use base64::{prelude::BASE64_STANDARD, Engine};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    traits::PublicKeyParts,
    Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;

/// RSA Padding Type
/// PKCS1v1_5 or PKCS1v2(OAEP)
#[wasm_bindgen]
#[derive(Default)]
pub enum PaddingType {
    #[default]
    PKCS1v1_5,
    PKCS1v2,
}

use wasm_bindgen::prelude::*;

/// RSA Encrypt Module
#[wasm_bindgen]
pub struct RSAEncrypt {
    // public key
    pub_key: RsaPublicKey,
    padding_type: PaddingType,
    plain_len: usize,
}
#[wasm_bindgen]
impl RSAEncrypt {
    /// padding_type: PKCS1v1_5 or PKCS1v2
    #[wasm_bindgen(constructor)]
    pub fn new(pub_key: String, padding_type: Option<PaddingType>) -> Self {
        let pub_key =
            RsaPublicKey::from_public_key_pem(&pub_key).expect_throw("public key decode failed");
        let padding_type = padding_type.unwrap_or(PaddingType::default());
        let plain_len = match padding_type {
            PaddingType::PKCS1v1_5 => pub_key.size() - 11,
            PaddingType::PKCS1v2 => pub_key.size() - 2 - 2 * 32,
        };
        Self {
            pub_key,
            padding_type,
            plain_len,
        }
    }
    /// RSA encrypt
    /// use public key to encrypt, encode plain_text and return cipher_text as base64
    #[wasm_bindgen]
    pub fn encrypt(&self, plain_text: &str) -> String {
        if plain_text.len() > self.plain_len {
            panic!("plain_text too long");
        }
        let mut rng = rand::thread_rng();
        // need optimize
        // I want to use match self.padding_typo => Pkcs1v15Encrypt or Oaep::new::<Sha256>(), It's need a type for between.
        let data = match self.padding_type {
            PaddingType::PKCS1v1_5 => self
                .pub_key
                .encrypt(&mut rng, Pkcs1v15Encrypt, plain_text.as_bytes())
                .expect_throw("failed to encrypt"),
            PaddingType::PKCS1v2 => self
                .pub_key
                .encrypt(&mut rng, Oaep::new::<Sha256>(), plain_text.as_bytes())
                .expect_throw("failed to encrypt"),
        };
        BASE64_STANDARD.encode(data)
    }
}
/// RSA  Decrypt Module
#[wasm_bindgen]
pub struct RSADecrypt {
    // private key
    pri_key: RsaPrivateKey,
    padding_type: PaddingType,
}
#[wasm_bindgen]
impl RSADecrypt {
    #[wasm_bindgen(constructor)]
    pub fn new(pri_key: String, padding_type: Option<PaddingType>) -> Self {
        let pri_key =
            RsaPrivateKey::from_pkcs8_pem(&pri_key).expect_throw("public key decode failed");
        let padding_type = padding_type.unwrap_or(PaddingType::default());
        Self {
            pri_key,
            padding_type,
        }
    }
    /// RSA decrypt
    /// use private key to decrypt, decode cipher_text and return plain_text as utf-8
    #[wasm_bindgen]
    pub fn decrypt(&self, cipher_text: &str) -> String {
        let data = BASE64_STANDARD
            .decode(cipher_text)
            .expect_throw("cipher_text decode failed");
        // need optimize
        // I want to use match self.padding_typo => Pkcs1v15Encrypt or Oaep::new::<Sha256>(), It's need a type for between.
        let plain = match self.padding_type {
            PaddingType::PKCS1v1_5 => self
                .pri_key
                .decrypt(Pkcs1v15Encrypt, &data)
                .expect_throw("failed to decrypt"),
            PaddingType::PKCS1v2 => self
                .pri_key
                .decrypt(Oaep::new::<Sha256>(), &data)
                .expect_throw("failed to decrypt"),
        };
        String::from_utf8(plain).expect_throw("utf-8 decode failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PUB_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsbSsKpmvOCWXctjAR6jF
uzw9aixW1gjA8z0nnT6yWbM8wBq7FZ7ZW0eFyxgo1ZmZQ315hcytwbh2/+TNN6tM
TDuDtw+vFfJ3IVZjIND7ZIuiqdt/dqIH0fjgjIf6GpyOv1nR7HGdewKzZFz4z8mx
e2BpmmqSyOsv05K/8OqCswoKjnZKUgb2XMYR+rPyenKPWHz7rbCPzXRL561mrdQy
R56YrneRAH9xYaSjujlnmWLac3/CxfkF7dxdZLflvJw2/iXKuVqE/tYDsN2JF2sK
UzhAP35G/PYIzADkcrDkqSZWMdRUrlJbS4dcvRudxeLWd2wkikwW4k3oq9ARqFog
9wIDAQAB
-----END PUBLIC KEY-----";
    const PRI_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCxtKwqma84JZdy
2MBHqMW7PD1qLFbWCMDzPSedPrJZszzAGrsVntlbR4XLGCjVmZlDfXmFzK3BuHb/
5M03q0xMO4O3D68V8nchVmMg0Ptki6Kp2392ogfR+OCMh/oanI6/WdHscZ17ArNk
XPjPybF7YGmaapLI6y/Tkr/w6oKzCgqOdkpSBvZcxhH6s/J6co9YfPutsI/NdEvn
rWat1DJHnpiud5EAf3FhpKO6OWeZYtpzf8LF+QXt3F1kt+W8nDb+Jcq5WoT+1gOw
3YkXawpTOEA/fkb89gjMAORysOSpJlYx1FSuUltLh1y9G53F4tZ3bCSKTBbiTeir
0BGoWiD3AgMBAAECggEAB8cJoZDgKQigJ1mFyz0ZCYsaTWf+YiS4IsBii11fzrdr
aViVWpD9ICN+7BCB7QNP2jMG9NlF7r+rjNYo0yhoncEddsKCRIDvQAksLBbPzqrV
cv8VbFqs4lg02U6BBQjxrtdE1EcOs00L2+pW+DhY6VAjBXkBNQQlSWqK6WwVTbYI
NwZvdGt5Lp9NQW8b/7UGAu6nz4Kn0GaQOig0KT8HlZIpvvzmQmSQbdfYJQ3CLkPh
wQQgwe9Rj4aQnCVkcfF6sq3tWbib8GANkW8o4M3/nYsKM0iNox5p2Wnd7tVyoJH3
UT2Q1Az3uPjAIXhrqdhVWc+RYcWEvwEra+ZlMmloZQKBgQDb/qHT9ig6MJZ8VhpA
I4jyYLJxaaycX/NfMBOwZaRA1XNqFJ61/oiAWhPQGa3hIDMwn4l7h+AW7ebHqzY/
6chVJnnek3JuKvbINqeWPeGcGejZrS+gKWF+pw07X5gX4X9psTAXgB6UX5tUAIQa
7pMALs0nk9MU85pHo6lTuLvNnQKBgQDOyja4mKyxCxfGM5WY2QoJW98uHdh5bMYV
SgF7rM0hT717Rbk4dq06DfDPDHe1WJzcYVQ8VJdE+xMyAMO9P7ZYX0KaYWe9fQEX
KX+GxPdp0e8l446W7uwf/HmNJdLUiw0HVLang2JcGhXUk4XM8xrkuHpubv9yCgUo
bdWDsuQuowKBgQCmnkAqrTDigZI4MW5ITaGXES2VQBf/h5xn553B5/lzMTbsjRl3
dYQk0hRXdFuBOkYK+YnDCbHrK9uyNjYsSf/0neOHc90jG181XE+pNsz80ZLN6qE7
iJvStOsMoOYskBlUD2MBKYP/lDmscYecbjzf0pKG+yrPn4Cl6YqBYlS68QKBgQCp
SSuA9SOykAU3cbVO+qbXwIk1RKOZy+1hMkOCjpUjZxcUWqDl02m+c/kmVuuM3u0T
EO6XsRxhETXGoo+bVxQcxmdM4N6/Zh1Fa+iFWKu+ymj/2Ik7kH5nNRYA8ezlqKvS
y4v4GHumMIicjORlQsNKaKd5zo56Oi+8yCWZ+hIJBwKBgQCufFa99k/MXnBxJ9Va
wnIFtOxHsLU0/bIjPDYhDQJUWAJs6N+j8zcDaPH2lK1ZLMhjvIYdGgyBtoph9lks
X8rxXBTDVWmTYmrulzm2CEldgMDbIop1LTsB2z6LyGuRE+5gt6PrN2LMswzYpTka
Aw5wUzwt7PIaWOUC/ps1wh8JMw==
-----END PRIVATE KEY-----";
    #[test]
    fn test_pkcs1v15_encrypt_decrypt() {
        let pub_key = String::from(PUB_KEY);
        let pri_key = String::from(PRI_KEY);

        let rsa_encrypt = RSAEncrypt::new(pub_key, Some(PaddingType::PKCS1v1_5));
        let rsa_decrypt = RSADecrypt::new(pri_key, Some(PaddingType::PKCS1v1_5));

        let plain_text = "Hello, World!";
        let cipher_text = rsa_encrypt.encrypt(plain_text);
        let decrypted_text = rsa_decrypt.decrypt(&cipher_text);
        println!("cipher_text: {}", cipher_text);
        println!("decrypted_text: {}", decrypted_text);
        assert_eq!(plain_text, decrypted_text);
    }
    #[test]
    fn test_pkcs1v2_encrypt_decrypt() {
        let pub_key = String::from(PUB_KEY);
        let pri_key = String::from(PRI_KEY);

        let rsa_encrypt = RSAEncrypt::new(pub_key, Some(PaddingType::PKCS1v2));
        let rsa_decrypt = RSADecrypt::new(pri_key, Some(PaddingType::PKCS1v2));

        let plain_text = "Hello, World!";
        let cipher_text = rsa_encrypt.encrypt(plain_text);
        let decrypted_text = rsa_decrypt.decrypt(&cipher_text);
        println!("cipher_text: {}", cipher_text);
        println!("decrypted_text: {}", decrypted_text);
        assert_eq!(plain_text, decrypted_text);
    }
}
