[中文版](README.zh_CN.md)

# smcrypto

A rust implementation of China's standards of encryption algorithms(SM2/SM3/SM4). Thanks for the python project [GMSSL](https://github.com/duanhongyi/gmssl).

## Installation

To use in your own rust project, add `Cargo.toml` of the `[dependencies]` item: 

```
smcrypto = "0.1.0"
```

Then in your `main.rs`: 

```
use smcrypto::*;
```

## SM3

```
let sm3_hash = sm3::sm3_hash(b"abc");
println!("sm3 hash is {}", sm3_hash);
```

You can hash one file as follows: 

```
let sm3_hash_file = sm3::sm3_hash_file("C:/Users/yumeng/Desktop/driver.exe");
println!("sm3 hash file is {}", sm3_hash_file);
```

## SM2

### Generate Key Pair

```
let (private_key, public_key) = sm2::gen_keypair();
```

You can use `OpenSSL` to generate a key pair. `openssl` must be installed and the executable file `openssl` should in system PATH.

```
let (private_key, public_key) = sm2::gen_keypair_openssl();
```

You can generate a pem file by `openssl`, and then import it.

```
openssl ecparam -genkey -name SM2 -out sk.pem
```

then: 

```
let (private_key, public_key) = sm2::keypair_from_pem_file("C:/Users/yumeng/sk.pem");
```

### Export Public Key 

```
let pk = sm2::pk_from_sk("f63afd2aa3550a83362e54dd4111a21043d4498f102eed96b70330bd63e6a8e7");
```

### Initialize CryptSM2

When the `mode` parameter is `1`, it uses `C1C3C2`, otherwise uses `C1C2C3`.

```
let sm2 = sm2::CryptSM2::new(&private_key, &public_key, 1);
```

### Sign and Verify

```
let data = b"I love Rust.";
let sign = sm2.sign(data);
println!("sm2 sign result is {}", sign);
let verify = sm2.verify(sign, data);
println!("sm2 verify result is {}", verify);
```

### Sign and Verify using SM3

```
let sign_sm3 = sm2.sign_with_sm3(data);
println!("sm2 sign_sm3 result is {}", sign_sm3);
let verify_sm3 = sm2.verify_with_sm3(data, sign_sm3);
println!("sm2 verify_sm3 result is {}", verify_sm3);
```

### Encrypt and Decrypt

```
let encrypt = sm2.encrypt(data);
println!("sm2 encryped data is {}", encrypt);
let decrypt = sm2.decrypt(encrypt);
println!("sm2 decryped data is {}", String::from_utf8(decrypt).unwrap());
```

### Encrypt and Decrypt Files

```
sm2.encrypt_to_file("C:/Users/yumeng/Desktop/putty.txt", "C:/Users/yumeng/Desktop/putty_sm2_crypt.txt");
sm2.decrypt_from_file("C:/Users/yumeng/Desktop/putty_sm2_crypt.txt", "C:/Users/yumeng/Desktop/putty_sm2_decrypt.txt");
```

## SM4

### Specify a Key

```
let key = "1234567812345678";
let value = b"A language empowering everyone to build reliable and efficient software.";
let iv = "0000000000000000";
```

### Encrypt and Decrypt(ECB)

```
let sm4_ecb = sm4::CryptSM4ECB::new(key);
let sm4_ecb_encrypt = sm4_ecb.encrypt_ecb(value);
println!("sm4 ecb encrypt is {}", sm4_ecb_encrypt);
let sm4_ecb_decrypt = sm4_ecb.decrypt_ecb(sm4_ecb_encrypt);
println!("sm4 ecb decrypt string is {}", String::from_utf8(sm4_ecb_decrypt).unwrap());
```

### Encrypt and Decrypt Files(ECB)

```
sm4_ecb.encrypt_to_file("C:/Users/yumeng/Desktop/putty.txt", "C:/Users/yumeng/Desktop/putty_encrypt_ecb.txt");
sm4_ecb.decrypt_from_file("C:/Users/yumeng/Desktop/putty_encrypt_ecb.txt", "C:/Users/yumeng/Desktop/putty_decrypt_ecb.txt");
```

### Encrypt and Decrypt(CBC)

```
let sm4_cbc = sm4::CryptSM4CBC::new(key, iv);
let sm4_cbc_encrypt = sm4_cbc.encrypt_cbc(value);
println!("sm4 cbc encrypt is {}", sm4_cbc_encrypt);
let sm4_cbc_decrypt = sm4_cbc.decrypt_cbc(sm4_cbc_encrypt);
println!("sm4 cbc decrypt string is {}", String::from_utf8(sm4_cbc_decrypt).unwrap());
```

### Encrypt and Decrypt Files(CBC)

```
sm4_cbc.encrypt_to_file("C:/Users/yumeng/Desktop/putty.txt", "C:/Users/yumeng/Desktop/putty_encrypt_cbc.txt");
sm4_cbc.decrypt_from_file("C:/Users/yumeng/Desktop/putty_encrypt_cbc.txt", "C:/Users/yumeng/Desktop/putty_decrypt_cbc.txt");
```