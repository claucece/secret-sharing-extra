use criterion::{black_box, criterion_group, criterion_main, Criterion};

use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;
use rand::Rng;
use secret_sharing_extra::VerifiableSecretSharingRistretto;
use std::convert::TryInto;

pub fn new_random() -> Scalar {
    let mut rand_bytes = [0u8; 32];
    thread_rng().fill(&mut rand_bytes[..]);

    let tmp: [u8; 32] = rand_bytes[..].try_into().unwrap();
    Scalar::from_bytes_mod_order(tmp)
}

fn feldman_256(c: &mut Criterion) {
    let secret: Scalar = new_random();
    let mut vss = VerifiableSecretSharingRistretto {
        threshold: 10,
        share_amount: 256,
    };
    let (mut shares, mut commitments) = vss.split(&secret);
    let mut sub_shares = &shares[0..10];
    let mut recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 25,
        share_amount: 256,
    };
    (shares, commitments) = vss.split(&secret);
    sub_shares = &shares[0..25];
    recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 50,
        share_amount: 256,
    };
    (shares, commitments) = vss.split(&secret);
    sub_shares = &shares[0..50];
    recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 100,
        share_amount: 256,
    };
    let (shares, commitments) = vss.split(&secret);
    let sub_shares = &shares[0..100];
    let recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 128,
        share_amount: 256,
    };
    let (shares, commitments) = vss.split(&secret);
    let sub_shares = &shares[0..128];
    let recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });
}

fn feldman_512(c: &mut Criterion) {
    let secret: Scalar = new_random();
    let mut vss = VerifiableSecretSharingRistretto {
        threshold: 10,
        share_amount: 512,
    };
    let (mut shares, mut commitments) = vss.split(&secret);
    let mut sub_shares = &shares[0..10];
    let mut recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 25,
        share_amount: 512,
    };
    (shares, commitments) = vss.split(&secret);
    sub_shares = &shares[0..25];
    recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 50,
        share_amount: 512,
    };
    (shares, commitments) = vss.split(&secret);
    sub_shares = &shares[0..50];
    recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });
    vss = VerifiableSecretSharingRistretto {
        threshold: 100,
        share_amount: 512,
    };
    (shares, commitments) = vss.split(&secret);
    sub_shares = &shares[0..100];
    recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });
    vss = VerifiableSecretSharingRistretto {
        threshold: 128,
        share_amount: 512,
    };
    (shares, commitments) = vss.split(&secret);
    sub_shares = &shares[0..128];
    recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });
}

fn feldman_768(c: &mut Criterion) {
    let secret: Scalar = new_random();
    let mut vss = VerifiableSecretSharingRistretto {
        threshold: 10,
        share_amount: 768,
    };
    let (mut shares, mut commitments) = vss.split(&secret);
    let mut sub_shares = &shares[0..10];
    let mut recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 25,
        share_amount: 768,
    };
    (shares, commitments) = vss.split(&secret);
    sub_shares = &shares[0..25];
    recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 50,
        share_amount: 768,
    };
    (shares, commitments) = vss.split(&secret);
    sub_shares = &shares[0..50];
    recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 100,
        share_amount: 768,
    };
    let (shares, commitments) = vss.split(&secret);
    let sub_shares = &shares[0..100];
    let recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 128,
        share_amount: 768,
    };
    let (shares, commitments) = vss.split(&secret);
    let sub_shares = &shares[0..128];
    let recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });
}

fn feldman_1024(c: &mut Criterion) {
    let secret: Scalar = new_random();
    let mut vss = VerifiableSecretSharingRistretto {
        threshold: 10,
        share_amount: 1024,
    };
    let (mut shares, mut commitments) = vss.split(&secret);
    let mut sub_shares = &shares[0..10];
    let mut recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 25,
        share_amount: 1024,
    };
    (shares, commitments) = vss.split(&secret);
    sub_shares = &shares[0..25];
    recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 50,
        share_amount: 1024,
    };
    (shares, commitments) = vss.split(&secret);
    sub_shares = &shares[0..50];
    recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 100,
        share_amount: 1024,
    };
    let (shares, commitments) = vss.split(&secret);
    let sub_shares = &shares[0..100];
    let recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 128,
        share_amount: 1024,
    };
    let (shares, commitments) = vss.split(&secret);
    let sub_shares = &shares[0..128];
    let recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });
}

fn feldman_1280(c: &mut Criterion) {
    let secret: Scalar = new_random();
    let mut vss = VerifiableSecretSharingRistretto {
        threshold: 10,
        share_amount: 1280,
    };
    let (mut shares, mut commitments) = vss.split(&secret);
    let mut sub_shares = &shares[0..10];
    let mut recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 25,
        share_amount: 1280,
    };
    (shares, commitments) = vss.split(&secret);
    sub_shares = &shares[0..25];
    recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 50,
        share_amount: 1280,
    };
    (shares, commitments) = vss.split(&secret);
    sub_shares = &shares[0..50];
    recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 100,
        share_amount: 1280,
    };
    let (shares, commitments) = vss.split(&secret);
    let sub_shares = &shares[0..100];
    let recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 128,
        share_amount: 1280,
    };
    let (shares, commitments) = vss.split(&secret);
    let sub_shares = &shares[0..128];
    let recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });
}

fn feldman_1536(c: &mut Criterion) {
    let secret: Scalar = new_random();
    let mut vss = VerifiableSecretSharingRistretto {
        threshold: 10,
        share_amount: 1536,
    };
    let (mut shares, mut commitments) = vss.split(&secret);
    let mut sub_shares = &shares[0..10];
    let mut recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 25,
        share_amount: 1536,
    };
    (shares, commitments) = vss.split(&secret);
    sub_shares = &shares[0..25];
    recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 50,
        share_amount: 1536,
    };
    (shares, commitments) = vss.split(&secret);
    sub_shares = &shares[0..50];
    recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 100,
        share_amount: 1536,
    };
    let (shares, commitments) = vss.split(&secret);
    let sub_shares = &shares[0..100];
    let recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 128,
        share_amount: 1536,
    };
    let (shares, commitments) = vss.split(&secret);
    let sub_shares = &shares[0..128];
    let recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });
}

fn feldman_1792(c: &mut Criterion) {
    let secret: Scalar = new_random();
    let mut vss = VerifiableSecretSharingRistretto {
        threshold: 10,
        share_amount: 1792,
    };
    let (mut shares, mut commitments) = vss.split(&secret);
    let mut sub_shares = &shares[0..10];
    let mut recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 25,
        share_amount: 1792,
    };
    (shares, commitments) = vss.split(&secret);
    sub_shares = &shares[0..25];
    recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 50,
        share_amount: 1792,
    };
    (shares, commitments) = vss.split(&secret);
    sub_shares = &shares[0..50];
    recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 100,
        share_amount: 1792,
    };
    let (shares, commitments) = vss.split(&secret);
    let sub_shares = &shares[0..100];
    let recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 128,
        share_amount: 1792,
    };
    let (shares, commitments) = vss.split(&secret);
    let sub_shares = &shares[0..128];
    let recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });
}

fn feldman_2048(c: &mut Criterion) {
    let secret: Scalar = new_random();
    let mut vss = VerifiableSecretSharingRistretto {
        threshold: 10,
        share_amount: 2048,
    };
    let (mut shares, mut commitments) = vss.split(&secret);
    let mut sub_shares = &shares[0..10];
    let mut recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 25,
        share_amount: 2048,
    };
    (shares, commitments) = vss.split(&secret);
    sub_shares = &shares[0..25];
    recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 50,
        share_amount: 2048,
    };
    (shares, commitments) = vss.split(&secret);
    sub_shares = &shares[0..50];
    recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 100,
        share_amount: 2048,
    };
    let (shares, commitments) = vss.split(&secret);
    let sub_shares = &shares[0..100];
    let recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });

    vss = VerifiableSecretSharingRistretto {
        threshold: 128,
        share_amount: 2048,
    };
    let (shares, commitments) = vss.split(&secret);
    let sub_shares = &shares[0..128];
    let recovered = vss.recover(&sub_shares);
    c.bench_function("verify_secret", |b| {
        b.iter(|| {
            VerifiableSecretSharingRistretto::verify_all(black_box(shares.as_slice()), &commitments)
        })
    });
}

criterion_group!(benches, feldman_256); // change to the appropriate parameter

criterion_main!(benches);
