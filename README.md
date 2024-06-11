# RS-Crypto
A simple crypto library, based on Rust and WebAssembly.

[![MIT LICENSE](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square&label=LICENSE)](https://github.com/yangxu52/rs-crypto/blob/main/LICENSE)&nbsp;
![GitHub Stars](https://img.shields.io/github/stars/yangxu52/rs-crypto.svg?style=flat-square&label=Stars&logo=github)&nbsp;
![GitHub Forks](https://img.shields.io/github/forks/yangxu52/rs-crypto.svg?style=flat-square&label=Forks&logo=github)
&emsp;

## Usage
Vite example:

### 1. Install RS-Crypto
use your favorite package manager.

``` shell
pnpm install rs-crypto
```

### 2. Add Optimize Exclude
In your project's `vite.config.ts` or `vite.config.js`:

```js
{
    ...
    optimizeDeps: {
        exclude: ['rs-crypto'],
    },
    ...
}
```

### 3. Initialize WebAssembly Module
In your project's entry, default `main.ts` or `main.js`:

```js
...
import init from 'rs-crypto';
await init();
...
```

### 4. Use Crypto Functions

#### 4.1 Require a key: Example `RSA` encrypt/decrypt

1. Import `RSAEncrypt` or `RSADecrypt` Class
2. Instantiate `RSAEncrypt` or `RSADecrypt`
3. Using instances to call methods
   
```js
import { RSAEncrypt, RSADecrypt } from 'rs-crypto'

// encrypt
const rsaEnc = new RSAEncrypt(public_key) // PKCS#8 Text
const cipherText1 = rsaEnc.encrypt('hello world')
const cipherText2 = rsaEnc.encrypt('hello rust')

// decrypt
const rsaDec = new RSADecrypt(private_key) // PKCS#8 Text
const plainText1 = rsaDec.decrypt(cipherText1)
const plainText2 = rsaDec.decrypt(cipherText2)
```

#### 4.2 Not require a key: Example `MD5` digest

1. Import `MD5` Method
2. Call Method.
   
```js
import { MD5 } from 'rs-crypto'
const digest = MD5(need_to_digest)
```

## Roadmap
- [ ] Crypto Methods
  - [x] RSA
  - [ ] AES
  - [ ] SHA1
  - [ ] SHA256
  - [ ] ……
- [ ] Performance Optimization
- [ ] Human Readable

## Contributors

  - Author: [yangxu52](https://github.com/yangxu52)   <small>*A Junior Rust developer*</small>

**Invite you to collaborate with me to maintain the repository together**

## Star History
<img src="https://api.star-history.com/svg?repos=yangxu52/rs-crypto&type=Date" alt="Star History" >

## License
MIT License  