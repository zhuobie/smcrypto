use criterion::{black_box, criterion_group, criterion_main, Criterion};
use smcrypto::{sm2, sm3, sm4};

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("SM3 Hash", |b| {
        b.iter(|| sm3::sm3_hash(black_box(b"dummy")))
    });

    c.bench_function("SM2 Gen Key Pair", |b| {
        b.iter(|| {
            sm2::gen_keypair();
        })
    });

    let (sk, pk) = sm2::gen_keypair();
    c.bench_function("SM2 Encrypt", |b| {
        b.iter(|| {
            let enc_ctx = sm2::Encrypt::new(black_box(&pk));
            enc_ctx.encrypt(black_box(b"dummy"))
        })
    });

    let enc_ctx = sm2::Encrypt::new(&pk);
    let enc = enc_ctx.encrypt(black_box(b"dummy"));
    c.bench_function("SM2 Decrypt", |b| {
        b.iter(|| {
            let dec_ctx = sm2::Decrypt::new(black_box(&sk));
            dec_ctx.decrypt(black_box(&enc))
        })
    });

    let key = b"1234567812345678";

    let sm4_ecb = sm4::CryptSM4ECB::new(key);
    c.bench_function("SM4 ECB Encrypt", |b| {
        b.iter(|| {
            sm4_ecb.encrypt_ecb(black_box(b"abc"));
        })
    });

    let enc_ecb = sm4_ecb.encrypt_ecb(b"abc");
    c.bench_function("SM4 ECB Decrypt", |b| {
        b.iter(|| {
            sm4_ecb.decrypt_ecb(black_box(&enc_ecb));
        })
    });

    let iv = b"0000000000000000";
    let sm4_cbc = sm4::CryptSM4CBC::new(key, iv);
    c.bench_function("SM4 CBC Encrypt", |b| {
        b.iter(|| {
            sm4_cbc.encrypt_cbc(black_box(b"abc"));
        })
    });

    let enc_cbc = sm4_cbc.encrypt_cbc(b"abc");
    c.bench_function("SM4 CBC Decrypt", |b| {
        b.iter(|| {
            sm4_cbc.decrypt_cbc(black_box(&enc_cbc));
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
