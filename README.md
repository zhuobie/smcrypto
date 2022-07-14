# smcrypto

A rust implementation of China's standards of encryption algorithms(SM2/SM3/SM4).

## Quick Start

### SM3

```
let hash = sm3::sm3_hash(b"abc");
assert_eq!(hash, "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
```

### SM2 Key Generate

Note that the public key is in hexadecimal format and does not contain the "04" prefix.

```
let (sk, pk) = sm2::gen_keypair();
```

### SM2 Sign/Verify

```
let sign_ctx = sm2::Sign::new(&sk);
let sign = sign_ctx.sign(b"abc");
let verify_ctx = sm2::Verify::new(&pk);
let verify = verify_ctx.verify(b"abc", &sign);
assert_eq!(verify, true);
```

### SM2 Encrypt/Decrypt

```
let enc_ctx = sm2::Encrypt::new(&pk);
let enc = enc_ctx.encrypt(b"abc");
let dec_ctx = sm2::Decrypt::new(&sk);
let dec = dec_ctx.decrypt(&enc);
assert_eq!(String::from_utf8(dec).unwrap(), "abc");
```

### SM2 Key Exchange

```
// Step 1
// a side
let ida = b"id_a@company.com";
let (ska, _) = sm2::gen_keypair();
let keyexchange_a = sm2::KeyExchange::new(ida, &ska);
let (a2b, rska) = keyexchange_a.keyexchange_1ab(16);
// b side
let idb = b"id_b@company.com";
let (skb, _) = sm2::gen_keypair();
let keyexchange_b = sm2::KeyExchange::new(idb, &skb);
let (b2a, rskb) = keyexchange_b.keyexchange_1ab(16);
// Step 2
// a side
let ka = keyexchange_a.keyexchange_2a(&rska, &b2a);
// b side
let kb = keyexchange_b.keyexchange_2b(&rskb, &a2b);
// Step 3
assert_eq!(ka.k, kb.k);
assert_eq!(ka.s12, kb.s12);
```

### SM4 ECB Encrypt/Decrypt

```
let key = b"1234567812345678";
let sm4_ecb = sm4::CryptSM4ECB::new(key);
let enc_ecb = sm4_ecb.encrypt_ecb(b"abc");
let dec_ecb = sm4_ecb.decrypt_ecb(&enc_ecb);
assert_eq!(String::from_utf8(dec_ecb).unwrap(), "abc");
```

### SM4 CBC Encrypt/Decrypt

```
let key = b"1234567812345678";
let iv = b"0000000000000000";
let sm4_cbc = sm4::CryptSM4CBC::new(key, iv);
let enc_cbc = sm4_cbc.encrypt_cbc(b"abc");
let dec_cbc = sm4_cbc.decrypt_cbc(&enc_cbc);
assert_eq!(String::from_utf8(dec_cbc).unwrap(), "abc");
```