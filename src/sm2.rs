use crate::sm3::sm3_hash;
use std::collections::HashMap;
use num_bigint::BigUint;
use num_traits::*;
use num_integer::*;
use rand::seq::SliceRandom;
use std::process::Command;
use std::path::Path;
use std::fs;
use lazy_static::*;
use std::borrow::Cow;
use bytes::{BytesMut, BufMut};

lazy_static! {
    static ref ECC_TABLE: HashMap<&'static str, &'static str> = {
        let mut ecc_table = HashMap::new();
        ecc_table.insert("n", "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123");
        ecc_table.insert("p", "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
        ecc_table.insert("g", "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0");
        ecc_table.insert("a", "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC");
        ecc_table.insert("b", "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93");
        ecc_table
    };
    static ref PARA_LEN: usize = ECC_TABLE.get(&"n").unwrap().len();
    static ref ECC_N: &'static str = ECC_TABLE.get(&"n").unwrap();
    static ref ECC_P: &'static str = ECC_TABLE.get(&"p").unwrap();
    static ref ECC_G: &'static str = ECC_TABLE.get(&"g").unwrap();
    static ref ECC_A: &'static str = ECC_TABLE.get(&"a").unwrap();
    static ref ECC_B: &'static str = ECC_TABLE.get(&"b").unwrap();

    static ref ECC_A3: BigUint = {
        let ecc_a: BigUint = BigUint::from_str_radix(*ECC_A, 16).unwrap();
        let ecc_p: BigUint = BigUint::from_str_radix(*ECC_P, 16).unwrap();
        (ecc_a + BigUint::new(vec![3])) % ecc_p
    };
}

#[macro_export]
macro_rules! format_hex {
    ($a: expr) => {
        format!("{:0width$x}", $a, width = *PARA_LEN)
    };

    ($a: expr, $b: expr) => {
        format!("{:0width$x}{:0width$x}", $a, $b, width = *PARA_LEN)
    };

    ($a: expr, $($b: tt)*) => {
        format!("{:0width$x}{}", $a, format_hex!($($b)*), width = *PARA_LEN)
    }
}

fn submod(a: &BigUint, b: &BigUint, ecc_p: &BigUint) -> BigUint {
    if a >= b {
        (a - b) % ecc_p
    } else {
        let d = b - a;
        let e = d.div_ceil(ecc_p);
        e * ecc_p - d
    }
}

fn random_hex(x: usize) -> String {
    let c = vec!["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"];
    let mut s: String = "".to_string();
    for _ in 0..x {
        s += *c.choose(&mut rand::thread_rng()).unwrap();
    }
    s
}

fn appendzero(data: &[u8], size: usize) -> Vec<u8> {
    let mut zeroslice: Vec<u8> = Vec::new();
    for _ in 0..size {
        zeroslice.extend(vec![0]);
    }
    if data.len() < size {
        let mut zeroslice = (&zeroslice[0..size - data.len()]).to_vec();
        zeroslice.extend(data.to_vec());
        zeroslice.to_vec()
    } else {
        data.to_owned()
    }
}

fn concvec(vec1: &[u8], vec2: &[u8]) -> Vec<u8> {
    let mut vec1 = vec1.to_vec();
    vec1.extend(vec2);
    vec1
}

#[macro_export]
macro_rules! concvec {
    ($a: expr) => {
        $a.to_vec()
    };

    ($a: expr, $b: expr) => {
        concvec($a, $b)
    };

    ($a: expr, $($b: tt)*) => {
        concvec($a, &concvec!($($b)*))
    }
}

fn kdf(z: &[u8], klen: usize) -> Vec<u8> {
    let mut c: Vec<u8> = vec![];
    let mut ct = 0x00000001;
    let j = (klen + 31) / 32;
    for i in 0..j {
        let mut tmp: Vec<u8> = vec![];
        tmp.append(&mut z.to_vec());
        let mut buf = BytesMut::with_capacity(32);
        buf.put_u32(ct);
        tmp.append(&mut buf.to_vec());
        let hash = sm3_hash(&tmp);
        let mut hash = hex::decode(hash).unwrap();
        if i + 1 == j && klen % 32 != 0 {
            c.append(&mut hash[0..(klen % 32)].to_vec());
        } else {
            c.append(&mut hash);
        }
        ct += 1;
    }
    c
}

fn pubkey2point(public_key: &str) -> Point {
    Point {
        x: BigUint::from_str_radix(&public_key[0..*PARA_LEN], 16).unwrap(), 
        y: BigUint::from_str_radix(&public_key[*PARA_LEN..], 16).unwrap(), 
        z: BigUint::one()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct Point {
    x: BigUint, 
    y: BigUint, 
    z: BigUint
}

fn double_point(input: Point) -> Point {
    let (x1, y1, z1) = (input.x, input.y, input.z);
    let ecc_p = BigUint::from_str_radix(*ECC_P, 16).unwrap();
    let t6 = (&z1 * &z1) % &ecc_p; 
    let t2 = (&y1 * &y1) % &ecc_p;
    let t3 = (&x1 + &t6) % &ecc_p;
    let t4 = submod(&x1, &t6, &ecc_p);
    let t1 = (&t3 * &t4) % &ecc_p;
    let t3 = (&y1 * &z1) % &ecc_p;
    let mut t4 = (&t2 * BigUint::new(vec![8])) % &ecc_p;
    let t5 = (&x1 * &t4) % &ecc_p;
    let t1 = (&t1 * BigUint::new(vec![3])) % &ecc_p;
    let t6 = (&t6 * &t6) % &ecc_p;
    let t6 = (&*ECC_A3 * &t6) % &ecc_p;
    let t1 = (&t1 + &t6) % &ecc_p;
    let z3 = (&t3 + &t3) % &ecc_p;
    let t3 = (&t1 * &t1) % &ecc_p;
    let t2 = (&t2 * &t4) % &ecc_p;
    let x3 = submod(&t3, &t5, &ecc_p);
    if &t5 % BigUint::new(vec![2]) == BigUint::one() {
        let tt = &t5 + ((&t5 + &ecc_p) >> 1);
        t4 = submod(&tt, &t3, &ecc_p);
    } else {
        let tt = &t5 + (&t5 >> 1);
        t4 = submod(&tt, &t3, &ecc_p);
    }
    let t1 = (&t1 * &t4) % &ecc_p;
    let y3 = submod(&t1, &t2, &ecc_p);
    Point {
        x: x3, 
        y: y3, 
        z: z3
    }
}

fn add_point(p1: Point, p2: Point) -> Point {
    let (x1, y1, z1) = (p1.x, p1.y, p1.z);
    let (x2, y2) = (p2.x, p2.y);
    let ecc_p: BigUint = BigUint::from_str_radix(*ECC_P, 16).unwrap();
    let t1: BigUint = (&z1 * &z1) % &ecc_p;
    let t2: BigUint = (&y2 * &z1) % &ecc_p;
    let t3: BigUint = (&x2 * &t1) % &ecc_p;
    let t1: BigUint = (&t1 * &t2) % &ecc_p;
    let t2: BigUint = submod(&t3, &x1, &ecc_p);
    let t3: BigUint = (&t3 + &x1) % &ecc_p;
    let t4: BigUint = (&t2 * &t2) % &ecc_p;
    let t1 = submod(&t1, &y1, &ecc_p);
    let z3: BigUint = (&z1 * &t2) % &ecc_p;
    let t2: BigUint = (&t2 * &t4) % &ecc_p;
    let t3: BigUint = (&t3 * &t4) % &ecc_p;
    let t5: BigUint = (&t1 * &t1) % &ecc_p;
    let t4: BigUint = (&x1 * &t4) % &ecc_p;
    let x3: BigUint = submod(&t5, &t3, &ecc_p);
    let t2: BigUint = (&y1 * &t2) % &ecc_p;
    let t3: BigUint = submod(&t4, &x3, &ecc_p);
    let t1: BigUint = (&t1 * &t3) % &ecc_p;
    let y3: BigUint = submod(&t1, &t2, &ecc_p);
    Point {
        x: x3, 
        y: y3, 
        z: z3
    }
}

fn convert_jacb_to_nor(point: Point) -> Point {
    let ecc_p: BigUint = BigUint::from_str_radix(*ECC_P, 16).unwrap();
    let (x, y, z) = (point.x, point.y, point.z);
    let z_1 = z.clone();
    let z_inv: BigUint = z.modpow(&(&ecc_p - BigUint::new(vec![2])), &ecc_p);
    let z_invsquar: BigUint = (&z_inv * &z_inv) % &ecc_p;
    let z_invqube: BigUint = (&z_invsquar * &z_inv) % &ecc_p;
    let x_new: BigUint = (&x * &z_invsquar) % &ecc_p;
    let y_new: BigUint = (&y * &z_invqube) % &ecc_p;
    let z_new: BigUint = (&z_1 * &z_inv) % &ecc_p;
    if z_new == BigUint::one() {
        Point {
            x: x_new, 
            y: y_new, 
            z: z_new
        }
    } else {
        Point {
            x: BigUint::zero(), 
            y: BigUint::zero(), 
            z: BigUint::zero()
        }
    }
}

fn kg(k: BigUint, point: &str) -> Point {
    let mut k = k;
    let point: String = point.to_string() + "1";
    let point = Point {
        x: BigUint::from_str_radix(&point[0..*PARA_LEN], 16).unwrap(),
        y: BigUint::from_str_radix(&point[*PARA_LEN..(*PARA_LEN * 2)], 16).unwrap(), 
        z: BigUint::from_str_radix(&point[(*PARA_LEN * 2)..], 16).unwrap()
    };
    let mut mask_str = "8".to_string();
    for _ in 0..((*PARA_LEN) - 1) {
        mask_str += "0";
    }
    let mask: BigUint = BigUint::from_str_radix(&mask_str, 16).unwrap();
    let mut temp = point.clone();
    let mut flag = false;
    for _ in 0..(*PARA_LEN * 4) {
        if flag {
            temp = double_point(temp);
        } 
        if &k & &mask != BigUint::zero() {
            if flag {
                temp = add_point(temp, point.clone());
            } else {
                flag = true;
                temp = point.clone();
            }
        }
        k = k << 1;
    }
    convert_jacb_to_nor(temp)
}

/// Check whether the public key is legal. The input public key may or may not contain the "04" prefix.

pub fn pubkey_valid(public_key: &str) -> bool {    
    let public_key = pubkey_trim(public_key);
    let x: &str = &public_key[0..64];
    let y: &str = &public_key[64..128];
    let x = BigUint::from_str_radix(x, 16).unwrap();
    let y = BigUint::from_str_radix(y, 16).unwrap();
    let a = BigUint::from_str_radix(*ECC_A, 16).unwrap();
    let b = BigUint::from_str_radix(*ECC_B, 16).unwrap();
    let p = BigUint::from_str_radix(*ECC_P, 16).unwrap();
    let np0 = kg(BigUint::from_str_radix(*ECC_N, 16).unwrap(), &public_key) == Point {x: BigUint::zero(), y: BigUint::zero(), z: BigUint::zero()};
    let on_curve = (&y * &y) % &p == (&x * &x * &x + &a * &x + &b) % &p;
    np0 && on_curve
}

fn pubkey_trim<'a>(public_key: &'a str) -> Cow<'a, str> {
    if public_key.len() == 130 && &public_key[0..2] == "04" {
        Cow::Borrowed(&public_key[2..])
    } else {
        Cow::Borrowed(public_key)
    }
}

fn keypair_from_pem_bytes(pem_bytes: Vec<u8>) -> (String, String) {
    let pem = pem::parse(pem_bytes).unwrap();
    let keyfield = pem.contents;
    let priv_key = hex::encode(&keyfield[36..68]);
    let pub_key = hex::encode(&keyfield[74..138]);
    let pub_key = if !pubkey_valid(&pub_key) && &pub_key[0..2] == "04" {
        hex::encode(&keyfield[75..139])
    } else {
        pub_key
    };
    (priv_key, pub_key)
}

/// Export private/public key from pem file. The pem file should be in pkcs8 format and unencryped.

pub fn keypair_from_pem_file(pem_file: &str) -> (String, String) {
    let pem_file_path = Path::new(pem_file);
    let pem_bytes = fs::read(pem_file_path).unwrap();
    keypair_from_pem_bytes(pem_bytes)
}

fn pubkey_from_pem_bytes(pem_bytes: Vec<u8>) -> String {
    let pem = pem::parse(pem_bytes).unwrap();
    let keyfield = pem.contents;
    let pub_key = hex::encode(&keyfield[27..91]);
    pub_key
}

/// Export public key from pem file. The pem file should be in pkcs8 format and unencrypted.

pub fn pubkey_from_pem_file(pem_file: &str) -> String {
    let pem_file_path = Path::new(pem_file);
    let pem_bytes = fs::read(pem_file_path).unwrap();
    pubkey_from_pem_bytes(pem_bytes)
}

fn keypair_to_pem_bytes(private_key: &str) -> Vec<u8> {
    let public_key = pk_from_sk(private_key);
    let pem = "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420".to_string() + private_key + "a14403420004" + &public_key;
    let pem = hex::decode(pem).unwrap();
    let pem = base64::encode(pem);
    let pem = "-----BEGIN PRIVATE KEY-----".to_string() + "\n" + &pem[0..64] + "\n" + &pem[64..128] + "\n" + &pem[128..] + "\n-----END PRIVATE KEY-----\n";
    pem.into_bytes()
}

/// Dump the keypair from a private key to a pem file in unencryped pkcs8 format.

pub fn keypair_to_pem_file(private_key: &str, pem_file: &str) {
    let output_file = Path::new(pem_file);
    let pem_bytes = keypair_to_pem_bytes(private_key);
    fs::write(output_file, &pem_bytes[..]).unwrap();
}

fn pubkey_to_pem_bytes(public_key: &str) -> Vec<u8> {
    let public_key = pubkey_trim(public_key);
    let pem = "3059301306072a8648ce3d020106082a811ccf5501822d03420004".to_string() + &public_key;
    let pem = hex::decode(pem).unwrap();
    let pem = base64::encode(pem);
    let pem = "-----BEGIN PUBLIC KEY-----".to_string() + "\n" + &pem[0..64] + "\n" + &pem[64..] + "\n-----END PUBLIC KEY-----\n";
    pem.into_bytes()
}

/// Dump the public key to a pem file in unencryped pkcs8 format.

pub fn pubkey_to_pem_file(public_key: &str, pem_file: &str) {
    let output_file = Path::new(pem_file);
    let pem_bytes = pubkey_to_pem_bytes(public_key);
    fs::write(output_file, &pem_bytes[..]).unwrap();
}

/// A keypair can be generated by openssl. The `openssl` executable file must be in system PATH. Currently openssl 1.1.1 is supported.

pub fn gen_keypair_openssl() -> (String, String) {
    let output = if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", "openssl ecparam -genkey -name SM2 | openssl pkcs8 -topk8 -inform PEM -outform pem -nocrypt"]).output().expect("openssl generate faild.")
    } else {
        Command::new("sh").arg("-c").arg("openssl ecparam -genkey -name SM2 | openssl pkcs8 -topk8 -inform PEM -outform pem -nocrypt").output().expect("openssl generate faild.")
    };
    let output = output.stdout;
    keypair_from_pem_bytes(output)
}

pub fn gen_keypair() -> (String, String) {
    let d = random_hex(*PARA_LEN);
    let pa = kg(BigUint::from_str_radix(&d, 16).unwrap(), *ECC_G);
    let pa = format_hex!(pa.x, pa.y);
    (d, pa)
}

/// Calculate public key from a private key.

pub fn pk_from_sk(private_key: &str) -> String {
    let p = kg(BigUint::from_str_radix(private_key, 16).unwrap(), *ECC_G);
    format_hex!(p.x, p.y)
}

fn sign_raw(data: &[u8], private_key: &str) -> Vec<u8> {
    let e = BigUint::from_bytes_be(data);
    let d = BigUint::from_str_radix(private_key, 16).unwrap();
    let k = random_hex(*PARA_LEN);
    let k = BigUint::from_str_radix(&k, 16).unwrap();
    let k1 = k.clone();
    let p1 = kg(k, *ECC_G);
    let r = (e + p1.x) % BigUint::from_str_radix(*ECC_N, 16).unwrap();
    if r == BigUint::zero() || &r + &k1 == BigUint::from_str_radix(*ECC_N, 16).unwrap() {
        vec![]
    } else {
        let d_1: BigUint = (&d + BigUint::one()).modpow(&(BigUint::from_str_radix(*ECC_N, 16).unwrap() - BigUint::new(vec![2])), &BigUint::from_str_radix(*ECC_N, 16).unwrap());
        let s: BigUint = (&d_1 * (&k1 + &r) - &r) % BigUint::from_str_radix(*ECC_N, 16).unwrap();
        if s == BigUint::zero() {
            vec![]
    }   else {
            yasna::construct_der(|writer| {
                writer.write_sequence(|writer| {
                    writer.next().write_biguint(&r);
                    writer.next().write_biguint(&s);
                });
            })
        }
    }
}

fn verify_raw(data: &[u8], sign: &[u8], public_key: &str) -> bool {
    let (r, s) = yasna::parse_der(sign, |reader| {
        reader.read_sequence(|reader| {
            let r = reader.next().read_biguint()?;
            let s = reader.next().read_biguint()?;
            return Ok((r, s));
        })
    }).unwrap();
    let r1 = r.clone();
    let s1 = s.clone();
    let e = BigUint::from_bytes_be(data);
    let t = (r + s) % BigUint::from_str_radix(*ECC_N, 16).unwrap();
    let t1 = t.clone();
    if t == BigUint::zero() {
        false
    } else {
        let mut p1 = kg(s1, *ECC_G);
        let p2 = kg(t1, public_key);
        if p1 == p2 {
            p1 = double_point(p1);
        } else {
            p1 = add_point(p1, p2);
            p1 = convert_jacb_to_nor(p1);
        }
        let x = p1.x;
        r1 == (&e + &x) % BigUint::from_str_radix(*ECC_N, 16).unwrap()
    }
}

fn sign(id: &[u8], data: &[u8], private_key: &str) -> Vec<u8> {
    let public_key = pk_from_sk(private_key);
    let m_bar = concvec(&hex::decode(zab(&public_key, id)).unwrap(), data);
    let e = hex::decode(sm3_hash(&m_bar)).unwrap();
    sign_raw(&e, private_key)
}

fn verify(id: &[u8], data: &[u8], sign: &[u8], public_key: &str) -> bool {
    let m_bar = concvec(&hex::decode(zab(&public_key, id)).unwrap(), data);
    let e = hex::decode(sm3_hash(&m_bar)).unwrap();
    verify_raw(&e, sign, public_key)
}

fn sign_to_file(id: &[u8], data: &[u8], sign_file: &str, private_key: &str) {
    let sign_file = Path::new(sign_file);
    let sign_data = sign(id, data, private_key);
    fs::write(sign_file, &sign_data[..]).unwrap();
}

fn verify_from_file(id: &[u8], data: &[u8], sign_file: &str, public_key: &str) -> bool {
    let sign_file = Path::new(sign_file);
    let sign_data = fs::read(sign_file).unwrap();
    verify(id, data, &sign_data, public_key)
}

fn encrypt(data: &[u8], public_key: &str) -> Vec<u8> {
    let k = random_hex(*PARA_LEN);
    let c1xyz = kg(BigUint::from_str_radix(k.as_str(), 16).unwrap(), *ECC_G);
    let c1x = appendzero(&BigUint::to_bytes_be(&c1xyz.x), *PARA_LEN / 2);
    let c1y = appendzero(&BigUint::to_bytes_be(&c1xyz.y), *PARA_LEN / 2);
    let c1 = concvec(&c1x, &c1y);
    let xy = kg(BigUint::from_str_radix(k.as_str(), 16).unwrap(), public_key);
    let x2 = BigUint::to_bytes_be(&xy.x);
    let y2 = BigUint::to_bytes_be(&xy.y);
    let x2 = appendzero(&x2, *PARA_LEN / 2);
    let y2 = appendzero(&y2, *PARA_LEN / 2);
    let xy = concvec(&x2, &y2);
    let t = kdf(&xy, data.len());    
    let cipher = if BigUint::from_bytes_be(&t) == BigUint::zero() {
        b"".to_vec()
    } else {
        let c2 = BigUint::from_bytes_be(&data) ^ BigUint::from_bytes_be(&t);
        let c2 = BigUint::to_bytes_be(&c2);
        let c2 = appendzero(&c2, data.len());
        let h = concvec!(&x2, data, &y2);
        let c3 = sm3_hash(&h);
        let c3 = hex::decode(c3).unwrap();
        let cipher = concvec!(&c1, &c3, &c2);
        cipher
    };
    cipher
}

fn decrypt(data: &[u8], private_key: &str) -> Vec<u8> {
    let c1 = &data[0..64];
    let c2 = &data[96..];
    let xy = kg(BigUint::from_str_radix(private_key, 16).unwrap(), &hex::encode(c1));
    let x = appendzero(&BigUint::to_bytes_be(&xy.x), 32);
    let y = appendzero(&BigUint::to_bytes_be(&xy.y), 32);
    let xy = concvec(&x, &y);
    let t = kdf(&xy, c2.len());
    let result = if BigUint::from_bytes_be(&t) == BigUint::zero() {
        b"".to_vec()
    } else {
        BigUint::to_bytes_be(&(BigUint::from_bytes_be(&c2) ^ BigUint::from_bytes_be(&t)))
    };
    result
}

fn encrypt_c1c2c3(data: &[u8], public_key: &str) -> Vec<u8> {
    let cipher_c1c3c2 = encrypt(data, public_key);
    let c1 = &cipher_c1c3c2[0..64];
    let c3 = &cipher_c1c3c2[64..96];
    let c2 = &cipher_c1c3c2[96..];
    concvec!(c1, c2, c3)
}

fn decrypt_c1c2c3(data: &[u8], private_key: &str) -> Vec<u8> {
    let c1 = &data[0..64];
    let c2 = &data[64..(data.len() - 32)];
    let c3 = &data[(data.len() - 32)..];
    let cipher_c1c3c2 = concvec!(c1, c3, c2);
    decrypt(&cipher_c1c3c2, private_key)
}

fn encrypt_asna1(data: &[u8], public_key: &str) -> Vec<u8> {
    let cipher = encrypt(data, public_key);
    let x = BigUint::from_bytes_be(&cipher[0..32]);
    let y = BigUint::from_bytes_be(&cipher[32..64]);
    let sm3 = &cipher[64..96];
    let secret = &cipher[96..];
    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_biguint(&x);
            writer.next().write_biguint(&y);
            writer.next().write_bytes(&sm3);
            writer.next().write_bytes(&secret);
        });
    })
}

fn decrypt_asna1(data: &[u8], private_key: &str) -> Vec<u8> {
    let (x, y, sm3, secret) = yasna::parse_der(data, |reader| {
        reader.read_sequence(|reader| {
            let x = reader.next().read_biguint()?;
            let y = reader.next().read_biguint()?;
            let sm3 = reader.next().read_bytes()?;
            let secret = reader.next().read_bytes()?;
            return Ok((x, y, sm3, secret));
        })
    }).unwrap();
    let x = BigUint::to_bytes_be(&x);
    let y = BigUint::to_bytes_be(&y);
    let x = appendzero(&x, 32);
    let y = appendzero(&y, 32);
    let cipher = concvec!(&x, &y, &sm3, &secret);
    decrypt(&cipher, private_key)
}

fn encrypt_hex(data: &[u8], public_key: &str) -> String {
    hex::encode(encrypt(data, public_key))
}

fn decrypt_hex(data: &str, private_key: &str) -> Vec<u8> {
    decrypt(&hex::decode(data).unwrap(), private_key)
}

fn encrypt_base64(data: &[u8], public_key: &str) -> String {
    base64::encode(encrypt(data, public_key))
}

fn decrypt_base64(data: &str, private_key: &str) -> Vec<u8> {
    decrypt(&base64::decode(data).unwrap(), private_key)
}

fn encrypt_to_file(data: &[u8], enc_file: &str, public_key: &str) {
    let enc_file = Path::new(enc_file);
    let enc_data = encrypt_asna1(data, public_key);
    fs::write(enc_file, &enc_data[..]).unwrap();
}

fn decrypt_from_file(enc_file: &str, private_key: &str) -> Vec<u8> {
    let enc_file = Path::new(enc_file);
    let enc_data = fs::read(enc_file).unwrap();
    decrypt_asna1(&enc_data, private_key)
}

fn kexhat(x: BigUint) -> BigUint {
    let w_2: Vec<u8> = [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00].to_vec();
    let w_2 = BigUint::from_bytes_be(&w_2);
    &w_2 + (&x & (&w_2 - BigUint::new(vec![1])))
}

fn zab(public_key: &str, uid: &[u8]) -> String {
    let entla: usize = 8 * uid.len();
    let za = concvec!(
        &vec![((entla >> 8) & 0xFF) as u8, (entla & 0xFF) as u8], 
        uid, 
        &hex::decode(*ECC_A).unwrap(), 
        &hex::decode(*ECC_B).unwrap(), 
        &hex::decode(*ECC_G).unwrap(), 
        &hex::decode(public_key).unwrap()
    );
    sm3_hash(&za)
}

pub struct KeyExchangeResult {
    pub k: String, 
    pub s12: Vec<u8>
}

fn keyexchange_raw(klen: usize, ida: &[u8], idb: &[u8], private_key: &str, public_key: &str, r_private_key: &str, r_public_key: &str, is_a: bool) -> KeyExchangeResult {
    let x2hat = kexhat(BigUint::from_str_radix(&pk_from_sk(r_private_key)[0..64], 16).unwrap());
    let x2rb = x2hat * BigUint::from_str_radix(r_private_key, 16).unwrap();
    let tbt = BigUint::from_str_radix(private_key, 16).unwrap() + x2rb;
    let tb = tbt % BigUint::from_str_radix(*ECC_N, 16).unwrap();
    assert_eq!(pubkey_valid(r_public_key), true);
    let x1hat = kexhat(BigUint::from_str_radix(&r_public_key[0..64], 16).unwrap());    
    let kx1y1 = kg(x1hat, &r_public_key);
    let vxyt = add_point(pubkey2point(public_key), kx1y1);
    let vxyt = convert_jacb_to_nor(vxyt);
    let vxyt = format_hex!(vxyt.x, vxyt.y);
    let vxy = kg(tb, &vxyt);
    let vx = vxy.x;
    let vy = vxy.y;
    let pza = if is_a {
        pk_from_sk(private_key)
    } else {
        public_key.to_string()
    };
    let za = zab(&pza, ida);
    assert_eq!(vx == BigUint::zero() || vy == BigUint::zero(), false);
    let pzb = if !is_a {
        pk_from_sk(private_key)
    } else {
        public_key.to_string()
    };
    let zb = zab(&pzb, idb);
    let z = concvec!(
        &vx.to_bytes_be(), 
        &vy.to_bytes_be(), 
        &hex::decode(&za).unwrap(), 
        &hex::decode(&zb).unwrap()
    );
    let z = hex::encode(&z).into_bytes();
    let h1 = if !is_a {
        concvec!(
            &BigUint::to_bytes_be(&vx), 
            &za.into_bytes(), 
            &zb.into_bytes(), 
            &BigUint::to_bytes_be(&BigUint::from_str_radix(&pk_from_sk(&r_private_key)[0..64], 16).unwrap()), 
            &BigUint::to_bytes_be(&BigUint::from_str_radix(&pk_from_sk(&r_private_key)[64..], 16).unwrap()), 
            &BigUint::to_bytes_be(&BigUint::from_str_radix(&r_public_key[0..64], 16).unwrap()), 
            &BigUint::to_bytes_be(&BigUint::from_str_radix(&r_public_key[64..], 16).unwrap())
        )
    } else {
        concvec!(
            &BigUint::to_bytes_be(&vx), 
            &za.into_bytes(), 
            &zb.into_bytes(), 
            &BigUint::to_bytes_be(&BigUint::from_str_radix(&r_public_key[0..64], 16).unwrap()), 
            &BigUint::to_bytes_be(&BigUint::from_str_radix(&r_public_key[64..], 16).unwrap()), 
            &BigUint::to_bytes_be(&BigUint::from_str_radix(&pk_from_sk(&r_private_key)[0..64], 16).unwrap()), 
            &BigUint::to_bytes_be(&BigUint::from_str_radix(&pk_from_sk(&r_private_key)[64..], 16).unwrap())
        )
    };
    let hash = sm3_hash(&h1);
    let h2 = concvec!(
        &hex::decode("02").unwrap(), 
        &BigUint::to_bytes_be(&vy), 
        &hex::decode(&hash).unwrap()
    );
    let s1 = sm3_hash(&h2);
    let h3 = concvec!(
        &hex::decode("03").unwrap(), 
        &BigUint::to_bytes_be(&vy), 
        &hex::decode(&hash).unwrap()
    );
    let s2 = sm3_hash(&h3);
    KeyExchangeResult {
        k: hex::encode(kdf(&z, klen)), 
        s12: yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_bytes(&s1.into_bytes()); 
                writer.next().write_bytes(&s2.into_bytes());
            });
        })
    }
}

fn keyexchange_a(klen: usize, ida: &[u8], idb: &[u8], private_key_a: &str, public_key_b: &str, private_key_ar: &str, public_key_br: &str) -> KeyExchangeResult {
    keyexchange_raw(klen, ida, idb, private_key_a, public_key_b, private_key_ar, public_key_br, true)
}

fn keyexchange_b(klen: usize, idb: &[u8], ida: &[u8], private_key_b: &str, public_key_a: &str, private_key_br: &str, public_key_ar: &str) -> KeyExchangeResult {
    keyexchange_raw(klen, ida, idb, private_key_b, public_key_a, private_key_br, public_key_ar, false)
}

fn keyexchange_1ab(klen: usize, id: &[u8], private_key: &str) -> (Vec<u8>, String) {
    let public_key = pk_from_sk(private_key);
    let (private_key_r, public_key_r) = gen_keypair();
    (
        yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_u32(klen as u32);
                writer.next().write_bytes(id);
                writer.next().write_bytes(&public_key.into_bytes());
                writer.next().write_bytes(&public_key_r.into_bytes());
            });
        }), 
        private_key_r
    )
}

fn keyexchange_2a(id: &[u8], private_key: &str, private_key_r: &str, recive_bytes: &[u8]) -> KeyExchangeResult {
    let (klen, idb, public_key, public_key_r) = yasna::parse_der(recive_bytes, |reader| {
        reader.read_sequence(|reader| {
            let klen = reader.next().read_u32()?;
            let idb = reader.next().read_bytes()?;
            let public_key = reader.next().read_bytes()?;
            let public_key_r = reader.next().read_bytes()?;
            return Ok((klen, idb, public_key, public_key_r));
        })
    }).unwrap();
    let klen = klen as usize;
    let public_key = std::str::from_utf8(&public_key).unwrap();
    let public_key_r = std::str::from_utf8(&public_key_r).unwrap();
    keyexchange_a(klen, id, &idb, private_key, public_key, private_key_r, public_key_r)
}

fn keyexchange_2b(id: &[u8], private_key: &str, private_key_r: &str, recive_bytes: &[u8]) -> KeyExchangeResult {
    let (klen, ida, public_key, public_key_r) = yasna::parse_der(recive_bytes, |reader| {
        reader.read_sequence(|reader| {
            let klen = reader.next().read_u32()?;
            let ida = reader.next().read_bytes()?;
            let public_key = reader.next().read_bytes()?;
            let public_key_r = reader.next().read_bytes()?;
            return Ok((klen, ida, public_key, public_key_r));
        })
    }).unwrap();
    let klen = klen as usize;
    let public_key = std::str::from_utf8(&public_key).unwrap();
    let public_key_r = std::str::from_utf8(&public_key_r).unwrap();
    keyexchange_b(klen, id, &ida, private_key, public_key, private_key_r, public_key_r)
}

pub struct Sign<'a> {
    pub id: &'a [u8], 
    pub private_key: &'a str
}

impl<'a> Default for Sign<'a> {
    fn default() -> Self {
        Sign {id: b"1234567812345678", private_key: ""}
    }
}

impl<'a> Sign<'a> {
    /// Initialize a sm2 sign instance with default id b"1234567812345678".
    pub fn new(private_key: &'a str) -> Self {
        Sign {private_key: private_key, ..Sign::default()}
    }

    /// Initialize a sm2 sign instance with a custom id.
    pub fn new_with_id(id: &'a [u8], private_key: &'a str) -> Self {
        Sign {id: id, private_key: private_key}
    }

    /// Sign with sm3.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        sign(self.id, data, self.private_key)
    }

    /// Sign without sm3.
    pub fn sign_raw(&self, data: &[u8]) -> Vec<u8> {
        sign_raw(data, self.private_key)
    }

    pub fn sign_to_file(&self, data: &[u8], sign_file: &str) {
        sign_to_file(self.id, data, sign_file, self.private_key)
    }
}

pub struct Verify<'a> {
    pub id: &'a [u8], 
    pub public_key: Cow<'a, str>
}

impl<'a> Default for Verify<'a> {
    fn default() -> Self {
        Verify {id: b"1234567812345678", public_key: Cow::Borrowed("")}
    }
}

impl<'a> Verify<'a> {
    /// Initialize a sm2 verify instance with default id b"1234567812345678".
    pub fn new(public_key: &'a str) -> Self {
        let public_key = pubkey_trim(public_key);
        Verify{public_key: public_key, ..Verify::default()}
    }

    /// Initialize a sm2 verify instance with a custom id.
    pub fn new_with_id(id: &'a [u8], public_key: &'a str) -> Self {
        Verify {id: id, public_key: Cow::Borrowed(public_key)}
    }

    /// Verify with sm3.
    pub fn verify(&self, data: &[u8], sign: &[u8]) -> bool {
        verify(self.id, data, sign, &self.public_key)
    }

    /// Verify without sm3.
    pub fn verify_raw(&self, data: &[u8], sign: &[u8]) -> bool {
        verify_raw(data, sign, &self.public_key)
    }

    pub fn verify_from_file(&self, data: &[u8], sign_file: &str) -> bool {
        verify_from_file(self.id, data, sign_file, &self.public_key)
    }
}

pub struct Encrypt<'a> {
    pub public_key: Cow<'a, str> 
}

impl<'a> Encrypt<'a> {
    pub fn new(public_key: &'a str) -> Self {
        let public_key = pubkey_trim(public_key);
        Encrypt{public_key: public_key}
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        encrypt(data, &self.public_key)
    }

    pub fn encrypt_c1c2c3(&self, data: &[u8]) -> Vec<u8> {
        encrypt_c1c2c3(data, &self.public_key)
    }

    pub fn encrypt_asna1(&self, data: &[u8]) -> Vec<u8> {
        encrypt_asna1(data, &self.public_key)
    }

    pub fn encrypt_hex(&self, data: &[u8]) -> String {
        encrypt_hex(data, &self.public_key)
    }

    pub fn encrypt_base64(&self, data: &[u8]) -> String {
        encrypt_base64(data, &self.public_key)
    }

    pub fn encrypt_to_file(&self, data: &[u8], enc_file: &str) {
        encrypt_to_file(data, enc_file, &self.public_key)
    }
}

pub struct Decrypt<'a> {
    pub private_key: &'a str
}

impl<'a> Decrypt<'a> {
    pub fn new(private_key: &'a str) -> Self {
        Decrypt{private_key: private_key}
    }

    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        decrypt(data, self.private_key)
    }

    pub fn decrypt_c1c2c3(&self, data: &[u8]) -> Vec<u8> {
        decrypt_c1c2c3(data, self.private_key)
    }

    pub fn decrypt_asna1(&self, data: &[u8]) -> Vec<u8> {
        decrypt_asna1(data, self.private_key)
    }

    pub fn decrypt_hex(&self, data: &str) -> Vec<u8> {
        decrypt_hex(data, self.private_key)
    }

    pub fn decrypt_base64(&self, data: &str) -> Vec<u8> {
        decrypt_base64(data, self.private_key)
    }

    pub fn decrypt_from_file(&self, enc_file: &str) -> Vec<u8> {
        decrypt_from_file(enc_file, self.private_key)
    }
}

pub struct KeyExchange<'a> {
    pub id: &'a [u8], 
    pub private_key: &'a str
}

impl<'a> KeyExchange<'a> {
    pub fn new(id: &'a [u8], private_key: &'a str) -> Self {
        KeyExchange{id: id, private_key: private_key}
    }

    /// klen is the length of key to generate.
    pub fn keyexchange_1ab(&self, klen: usize) -> (Vec<u8>, String) {
        keyexchange_1ab(klen, self.id, self.private_key)
    }

    pub fn keyexchange_2a(&self, private_key_r: &str, recive_bytes: &[u8]) -> KeyExchangeResult {
        keyexchange_2a(self.id, self.private_key, private_key_r, recive_bytes)
    }

    pub fn keyexchange_2b(&self, private_key_r: &str, recive_bytes: &[u8]) -> KeyExchangeResult {
        keyexchange_2b(self.id, self.private_key, private_key_r, recive_bytes)
    }
}