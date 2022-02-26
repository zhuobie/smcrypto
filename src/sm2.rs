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

fn sm3_kdf(z: &[u8], klen: usize) -> String {
    let mut ct = 0x00000001;
    let rcnt = klen.div_ceil(&32);
    let zin = hex::decode(&z).unwrap();
    let mut ha = "".to_string();
    let mut msg = zin.clone();
    for _ in 0..rcnt {
        let mut temp = hex::decode(format!("{:08x}", ct)).unwrap();
        msg.append(& mut temp);
        ha += &sm3_hash(msg.as_slice());
        ct += 1;
    }
    let ha = ha.as_str();
    ha[0..klen * 2].to_string()
}

fn keypair_from_pem_bytes(pem_bytes: Vec<u8>) -> (String, String) {
    let pems = pem::parse_many(pem_bytes).unwrap();
    let keyfield = &pems[1].contents;
    let keyfield = keyfield.to_vec();
    let priv_key = hex::encode(&keyfield[07..39]);
    let pub_key = hex::encode(&keyfield[57..121]);
    (priv_key, pub_key)
}

pub fn keypair_from_pem_file(pem_file: &str) -> (String, String) {
    let pem_file_path = Path::new(pem_file);
    let pem_bytes = fs::read(pem_file_path).unwrap();
    keypair_from_pem_bytes(pem_bytes)
}

pub fn gen_keypair_openssl() -> (String, String) {
    let output = if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", "openssl ecparam -genkey -name SM2"]).output().expect("openssl generate faild.")
    } else {
        Command::new("sh").arg("-c").arg("openssl ecparam -genkey -name SM2").output().expect("openssl generate faild.")
    };
    let output = output.stdout;
    keypair_from_pem_bytes(output)
}

pub fn gen_keypair() -> (String, String) {
    let d = random_hex(*PARA_LEN);
    let pa = kg(BigUint::from_str_radix(&d, 16).unwrap(), *ECC_G);
    (d, pa)
}

pub fn pk_from_sk(private_key: &str) -> String {
    kg(BigUint::from_str_radix(private_key, 16).unwrap(), *ECC_G)
}

fn double_point(point: &str) -> String {
    let l = point.len();
    let len_2 = 2 * (*PARA_LEN);
    if l < (*PARA_LEN) * 2 {
        "None".to_string()
    } else {
        let x1: BigUint = BigUint::from_str_radix(&point[0..(*PARA_LEN)], 16).unwrap();
        let y1: BigUint = BigUint::from_str_radix(&point[(*PARA_LEN)..len_2], 16).unwrap();
        let z1: BigUint;
        if 1 == len_2 {
            z1 = BigUint::one();
        } else {
            z1 = BigUint::from_str_radix(&point[len_2..], 16).unwrap();
        }
        let ecc_p: BigUint = BigUint::from_str_radix(*ECC_P, 16).unwrap();
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
        format!("{:0width$x}{:0width$x}{:0width$x}", &x3, &y3, &z3, width = (*PARA_LEN))
    }
}

fn add_point(p1: &str, p2: &str) -> String {
    let len_2 = 2 * (*PARA_LEN);
    let l1 = p1.len();
    let l2 = p2.len();
    if l1 < len_2 || l2 < len_2 {
        "None".to_string()
    } else {
        let x1: BigUint = BigUint::from_str_radix(&p1[0..(*PARA_LEN)], 16).unwrap();
        let y1: BigUint = BigUint::from_str_radix(&p1[(*PARA_LEN)..len_2], 16).unwrap();
        let z1: BigUint;
        if l1 == len_2 {
            z1 = BigUint::one();
        } else {
            z1 = BigUint::from_str_radix(&p1[len_2..], 16).unwrap();
        }
        let x2: BigUint = BigUint::from_str_radix(&p2[0..(*PARA_LEN)], 16).unwrap();
        let y2: BigUint = BigUint::from_str_radix(&p2[(*PARA_LEN)..len_2], 16).unwrap();
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
        format!("{:0width$x}{:0width$x}{:0width$x}", &x3, &y3, &z3, width = (*PARA_LEN))
    }
}

fn convert_jacb_to_nor(point: &str) -> String {
    let ecc_p: BigUint = BigUint::from_str_radix(*ECC_P, 16).unwrap();
    let len_2 = 2 * (*PARA_LEN);
    let x: BigUint = BigUint::from_str_radix(&point[0..(*PARA_LEN)], 16).unwrap();
    let y: BigUint = BigUint::from_str_radix(&point[(*PARA_LEN)..len_2], 16).unwrap();
    let z: BigUint = BigUint::from_str_radix(&point[len_2..], 16).unwrap();
    let z_1 = z.clone();
    let z_inv: BigUint = z.modpow(&(&ecc_p - BigUint::new(vec![2])), &ecc_p);
    let z_invsquar: BigUint = (&z_inv * &z_inv) % &ecc_p;
    let z_invqube: BigUint = (&z_invsquar * &z_inv) % &ecc_p;
    let x_new: BigUint = (&x * &z_invsquar) % &ecc_p;
    let y_new: BigUint = (&y * &z_invqube) % &ecc_p;
    let z_new: BigUint = (&z_1 * &z_inv) % &ecc_p;
    if z_new == BigUint::one() {
        format!("{:0width$x}{:0width$x}", &x_new, &y_new, width = (*PARA_LEN))
    } else {
        "None".to_string()
    }

}

fn kg(k: BigUint, point: &str) -> String {
    let mut k = k;
    let point: String = point.to_string() + "1";
    let point: &str = point.as_str();
    let mut mask_str = "8".to_string();
    for _ in 0..((*PARA_LEN) - 1) {
        mask_str += "0";
    }
    let mask: BigUint = BigUint::from_str_radix(&mask_str, 16).unwrap();
    let mut temp: String = point.to_string();
    let mut flag = false;
    for _ in 0..((*PARA_LEN) * 4) {
        if flag {
            temp = double_point(temp.as_str());
        }
        if &k & &mask != BigUint::zero() {
            if flag {
                temp = add_point(temp.as_str(), point);
            } else {
                flag = true;
                temp = point.to_string();
            }
        }
        k = k << 1;
    }
    convert_jacb_to_nor(temp.as_str())
}

fn sign(data: &[u8], private_key: &str) -> String {
    let e = hex::encode(&data);
    let e = BigUint::from_str_radix(&e, 16).unwrap();
    let d = BigUint::from_str_radix(private_key, 16).unwrap();
    let k = random_hex(*PARA_LEN);
    let k = BigUint::from_str_radix(&k, 16).unwrap();
    let k1 = k.clone();
    let p1 = kg(k, *ECC_G);
    let x = BigUint::from_str_radix(&p1[0..(*PARA_LEN)], 16).unwrap();
    let r: BigUint = (e + x) % BigUint::from_str_radix(*ECC_N, 16).unwrap();
    if r == BigUint::zero() || &r + &k1 == BigUint::from_str_radix(*ECC_N, 16).unwrap() {
        "None".to_string()
    } else {
        let d_1: BigUint = (&d + BigUint::one()).modpow(&(BigUint::from_str_radix(*ECC_N, 16).unwrap() - BigUint::new(vec![2])), &BigUint::from_str_radix(*ECC_N, 16).unwrap());
        let s: BigUint = (&d_1 * (&k1 + &r) - &r) % BigUint::from_str_radix(*ECC_N, 16).unwrap();
        if s == BigUint::zero() {
            "None".to_string()
    }   else {
            format!("{:064x}{:064x}", &r, &s)
        }
    }
}

fn verify(sign: String, data: &[u8], public_key: &str) -> u32 {
    let r: BigUint = BigUint::from_str_radix(&sign[0..(*PARA_LEN)], 16).unwrap();
    let r1 = r.clone();
    let s: BigUint = BigUint::from_str_radix(&sign[(*PARA_LEN)..(2 * (*PARA_LEN))], 16).unwrap();
    let s1 = s.clone();
    let e = BigUint::from_str_radix(hex::encode(&data).as_str(), 16).unwrap();
    let t = (r + s) % BigUint::from_str_radix(*ECC_N, 16).unwrap();
    let t1 = t.clone();
    
    if t == BigUint::zero() {
        0
    } else {
        let mut p1 = kg(s1, *ECC_G);
        let p2 = kg(t1, public_key);
        if p1 == p2 {
            p1 += "1";
            p1 = double_point(&p1);
        } else {
            p1 += "1";
            p1 = add_point(&p1, &p2);
            p1 = convert_jacb_to_nor(&p1);
        }
        let x = BigUint::from_str_radix(&p1[0..(*PARA_LEN)], 16).unwrap();
        if r1 == (&e + &x) % BigUint::from_str_radix(*ECC_N, 16).unwrap() {
            1
        } else {
            0
        }
    }
}

fn encrypt(data: &[u8], public_key: &str, mode: usize) -> String {
    let msg: String = hex::encode(&data);
    let k: String = random_hex(*PARA_LEN);
    let c1: String = kg(BigUint::from_str_radix(k.as_str(), 16).unwrap(), *ECC_G);
    let xy: String = kg(BigUint::from_str_radix(k.as_str(), 16).unwrap(), public_key);
    let x2: &str = &xy[0..(*PARA_LEN)];
    let y2: &str = &xy[(*PARA_LEN)..(2 * (*PARA_LEN))];
    let ml: usize = msg.len();
    let t = sm3_kdf(&xy.as_bytes(), ml / 2);
    let result: Vec<u8>;
    if BigUint::from_str_radix(&t, 16).unwrap() == BigUint::zero() {
        result = "None".as_bytes().to_owned();
    } else {
        let c2 = format!("{:0width$x}", BigUint::from_str_radix(&msg, 16).unwrap() ^ BigUint::from_str_radix(&t, 16).unwrap(), width = &ml);
        let c3 = sm3_hash(&hex::decode(format!("{}{}{}", &x2, &msg, &y2)).unwrap());
        if mode == 1 {
            result = hex::decode(format!("{}{}{}", &c1, &c3, &c2)).unwrap().to_owned();
        } else {
            result = hex::decode(format!("{}{}{}", &c1, &c2, &c3)).unwrap().to_owned();
        }
    }
    base64::encode(&result)
}

fn decrypt(data: String, private_key: &str, mode: usize) -> Vec<u8> {
    let data = base64::decode(&data).unwrap();
    let data = hex::encode(&data);
    let len_2 = 2 * (*PARA_LEN);
    let len_3 = len_2 + 64;
    let c1 = &data[0..len_2];
    let c2: &str;
    if mode == 1 {
        c2 = &data[len_3..];
    } else {
        c2 = &data[len_2..(&data.len() - 64)];
    }
    let xy = kg(BigUint::from_str_radix(private_key, 16).unwrap(), &c1);
    let cc1 = c2.len();
    let t = sm3_kdf(&xy.as_bytes(), cc1 / 2);
    let result: String;
    if BigUint::from_str_radix(&t, 16).unwrap() == BigUint::zero() {
        result = "None".to_string();
    } else {
        let m = format!("{:0width$x}", BigUint::from_str_radix(&c2, 16).unwrap() ^ BigUint::from_str_radix(&t, 16).unwrap(), width = cc1);
        result = m;
    }
    hex::decode(&result).unwrap()
}

fn encrypt_to_file(input_file: &str, output_file: &str, public_key: &str, mode: usize) {
    let input_file = Path::new(input_file);
    let output_file = Path::new(output_file);
    let input_data = fs::read(input_file).unwrap();
    let output_data = encrypt(&input_data, public_key, mode);
    fs::write(output_file, &output_data[..]).unwrap();
}

fn decrypt_from_file(input_file: &str, output_file: &str, private_key: &str, mode: usize) {
    let input_file = Path::new(input_file);
    let output_file = Path::new(output_file);
    let input_data = fs::read(input_file).unwrap();
    let input_data = String::from_utf8(input_data).unwrap();
    let output_data = decrypt(input_data, private_key, mode);
    fs::write(output_file, &output_data[..]).unwrap();
}

fn sm3_z(data: &[u8], public_key: &str) -> String {
    let z: String = format!("{}{}{}{}{}{}", "0080", "31323334353637383132333435363738", *ECC_A, *ECC_B, *ECC_G, public_key);
    let z = hex::decode(z).unwrap();
    let za = sm3_hash(&z);
    let m = za + &hex::encode(data);
    let e = sm3_hash(&hex::decode(m).unwrap());
    e
}

fn sign_with_sm3(data: &[u8], private_key: &str, public_key: &str) -> String {
    let sign_data = hex::decode(sm3_z(&data, public_key)).unwrap();
    let sign = sign(&sign_data, private_key);
    sign
}

fn verify_with_sm3(data: &[u8], sign: String, public_key: &str) -> u32{
    let sign_data = hex::decode(sm3_z(&data, public_key)).unwrap();
    verify(sign, &sign_data, public_key)
}

pub struct CryptSM2 {
    pub private_key: String, 
    pub public_key: String, 
    pub mode: usize
}

impl CryptSM2 {
    pub fn new(private_key: &str, public_key: &str, mode: usize) -> Self {
        CryptSM2{private_key: private_key.to_string(), public_key: public_key.to_string(), mode: mode}
    }

    pub fn sign(&self, data: &[u8]) -> String {
        sign(data, &self.private_key)
    }

    pub fn verify(&self, sign: String, data: &[u8]) -> u32 {
        verify(sign, data, &self.public_key)
    }

    pub fn encrypt(&self, data: &[u8]) -> String {
        encrypt(data, &self.public_key, self.mode)
    }

    pub fn decrypt(&self, data: String) -> Vec<u8> {
        decrypt(data, &self.private_key, self.mode)
    }

    pub fn encrypt_to_file(&self, input_file: &str, output_file: &str) {
        encrypt_to_file(input_file, output_file, &self.public_key, self.mode)
    }

    pub fn decrypt_from_file(&self, input_file: &str, output_file: &str) {
        decrypt_from_file(input_file, output_file, &self.private_key, self.mode)
    }

    pub fn sign_with_sm3(&self, data: &[u8]) -> String {
        sign_with_sm3(data, &self.private_key, &self.public_key)
    }

    pub fn verify_with_sm3(&self, data: &[u8], sign: String) -> u32 {
        verify_with_sm3(data, sign, &self.public_key)
    }
}
