# smcrypto
国密加密算法SM2/SM3/SM4的Rust实现，重构自Python项目[GMSSL](https://github.com/duanhongyi/gmssl)，在此对该项目的作者表示感谢。

## 安装

要在本地Rust项目中引用，在`Cargo.toml`的`[dependencies]`条目中添加：

```
smcrypto = {path = "../smcrypto"}
```

然后在源代码中声明引用：

```
use smcrypto::*;
```

## SM3算法

```
let sm3_hash = sm3::sm3_hash(b"abc");
println!("sm3 hash is {}", sm3_hash);
```

也可以对本地文件进行hash：

```
let sm3_hash_file = sm3::sm3_hash_file("C:/Users/yumeng/Desktop/driver.exe");
println!("sm3 hash file is {}", sm3_hash_file);
```

## SM2算法

### 生成密钥对

```
let (private_key, public_key) = sm2::gen_keypair();
```

也可以调用本地安装的OpenSSL生成，这种情况需要本机安装OpenSSL，且`openssl`可执行程序必须在`PATH`内。对于Windows操作系统，可以安装[Win64 OpenSSL v1.1.1m Light](http://slproweb.com/products/Win32OpenSSL.html)。

```
let (private_key, public_key) = sm2::gen_keypair_openssl();
```

也可以使用`openssl`生成pem密钥文件后再导入，首先使用`openssl`生成密钥文件：

```
openssl ecparam -genkey -name SM2 -out sk.pem
```

从密钥文件中获取密钥对：

```
let (private_key, public_key) = sm2::keypair_from_pem_file("C:/Users/yumeng/sk.pem");
```

### 从私钥中导出公钥

```
let pk = sm2::pk_from_sk("f63afd2aa3550a83362e54dd4111a21043d4498f102eed96b70330bd63e6a8e7");
```

### 初始化SM2实例

`mode`参数为1时，使用`C1C3C2`，`mode`参数为0时，使用`C1C2C3`。

```
let sm2 = sm2::CryptSM2::new(&private_key, &public_key, 1);
```

### 签名和验签

```
let data = b"I love Rust.";
let sign = sm2.sign(data);
println!("sm2 sign result is {}", sign);
let verify = sm2.verify(sign, data);
println!("sm2 verify result is {}", verify);
```

### SM3签名和验签

```
let sign_sm3 = sm2.sign_with_sm3(data);
println!("sm2 sign_sm3 result is {}", sign_sm3);
let verify_sm3 = sm2.verify_with_sm3(data, sign_sm3);
println!("sm2 verify_sm3 result is {}", verify_sm3);
```

### 加密和解密

加密后的数据以base64编码。

```
let encrypt = sm2.encrypt(data);
println!("sm2 encryped data is {}", encrypt);
let decrypt = sm2.decrypt(encrypt);
println!("sm2 decryped data is {}", String::from_utf8(decrypt).unwrap());
```

### 文件的加密和解密

```
sm2.encrypt_to_file("C:/Users/yumeng/Desktop/putty.txt", "C:/Users/yumeng/Desktop/putty_sm2_crypt.txt");
sm2.decrypt_from_file("C:/Users/yumeng/Desktop/putty_sm2_crypt.txt", "C:/Users/yumeng/Desktop/putty_sm2_decrypt.txt");
```

## SM4算法

### 初始化SM4密钥

```
let key = "1234567812345678";
let value = b"A language empowering everyone to build reliable and efficient software.";
let iv = "0000000000000000";
```

### SM4 ECB加密和解密

```
let sm4_ecb = sm4::CryptSM4ECB::new(key);
let sm4_ecb_encrypt = sm4_ecb.encrypt_ecb(value);
println!("sm4 ecb encrypt is {}", sm4_ecb_encrypt);
let sm4_ecb_decrypt = sm4_ecb.decrypt_ecb(sm4_ecb_encrypt);
println!("sm4 ecb decrypt string is {}", String::from_utf8(sm4_ecb_decrypt).unwrap());
```

### SM4 ECB加密和解密（文件）

```
sm4_ecb.encrypt_to_file("C:/Users/yumeng/Desktop/putty.txt", "C:/Users/yumeng/Desktop/putty_encrypt_ecb.txt");
sm4_ecb.decrypt_from_file("C:/Users/yumeng/Desktop/putty_encrypt_ecb.txt", "C:/Users/yumeng/Desktop/putty_decrypt_ecb.txt");
```

### SM4 CBC加密和解密

```
let sm4_cbc = sm4::CryptSM4CBC::new(key, iv);
let sm4_cbc_encrypt = sm4_cbc.encrypt_cbc(value);
println!("sm4 cbc encrypt is {}", sm4_cbc_encrypt);
let sm4_cbc_decrypt = sm4_cbc.decrypt_cbc(sm4_cbc_encrypt);
println!("sm4 cbc decrypt string is {}", String::from_utf8(sm4_cbc_decrypt).unwrap());
```

### SM4 CBC加密和解密（文件）

```
sm4_cbc.encrypt_to_file("C:/Users/yumeng/Desktop/putty.txt", "C:/Users/yumeng/Desktop/putty_encrypt_cbc.txt");
sm4_cbc.decrypt_from_file("C:/Users/yumeng/Desktop/putty_encrypt_cbc.txt", "C:/Users/yumeng/Desktop/putty_decrypt_cbc.txt");
```