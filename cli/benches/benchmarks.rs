use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ff::Field;
use rand::rngs::OsRng;
use crypto_blstrs::{blstrs, blstrs_lagrange_G1Projective};
use crate::blstrs::{G2Projective, G1Affine, G1Projective, Scalar};
use group::{Curve, Group};
use crypto_blstrs::blstrs::pairing;

// This file contains some micro-benchmarks that were useful during the development.

/*
TODO this has been swapped
pub fn blstrs_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("BLSTRS");

    // Randomly generated
    let p1 = G1Projective::from_compressed(&[133, 33, 237, 69, 77, 214, 246, 104, 136, 165, 168, 158, 228, 36, 175, 80, 27, 196, 33, 184, 55, 24, 238, 242, 24, 96, 202, 115, 211, 231, 68, 27, 153, 150, 190, 43, 46, 192, 87, 157, 99, 96, 193, 224, 221, 109, 89, 151, 16, 62, 180, 139, 191, 224, 71, 210, 238, 140, 198, 114, 35, 164, 135, 27, 29, 66, 17, 181, 218, 27, 143, 204, 193, 53, 144, 228, 109, 201, 193, 24, 169, 30, 97, 150, 199, 90, 252, 54, 142, 19, 193, 42, 123, 246, 113, 23]).unwrap();
    let p2 = G1Projective::from_compressed(&[182, 188, 120, 195, 168, 184, 242, 56, 40, 237, 111, 45, 152, 136, 72, 46, 133, 136, 140, 144, 73, 118, 63, 132, 179, 153, 200, 191, 220, 215, 198, 75, 93, 218, 90, 60, 53, 60, 190, 138, 183, 157, 118, 190, 166, 145, 199, 40, 0, 229, 19, 54, 243, 119, 125, 226, 4, 146, 250, 101, 24, 0, 175, 48, 24, 237, 175, 31, 118, 143, 185, 214, 130, 60, 249, 134, 160, 195, 47, 33, 238, 174, 127, 123, 63, 100, 118, 40, 23, 92, 237, 252, 182, 71, 82, 137]).unwrap();

    let h1 = G2Projective::from_compressed(&[179, 43, 152, 114, 126, 85, 4, 219, 251, 134, 188, 126, 44, 44, 86, 251, 188, 102, 18, 141, 126, 177, 27, 207, 90, 57, 118, 50, 224, 85, 66, 221, 191, 14, 131, 138, 169, 78, 140, 104, 21, 227, 188, 227, 144, 114, 145, 66]).unwrap();
    let h2 = G2Projective::from_compressed(&[144, 42, 205, 147, 146, 120, 26, 2, 120, 82, 22, 49, 200, 164, 123, 237, 113, 76, 253, 170, 246, 97, 140, 59, 215, 190, 212, 137, 207, 24, 255, 144, 37, 20, 174, 77, 234, 203, 177, 128, 191, 37, 14, 36, 14, 102, 158, 96]).unwrap();

    let s = Scalar::from_bytes_be(&[22, 110, 91, 178, 168, 103, 193, 113, 99, 111, 90, 201, 104, 66, 68, 27, 3, 36, 75, 179, 48, 193, 124, 78, 194, 165, 100, 224, 192, 22, 235, 70]).unwrap();

    group.bench_function("G1Projective into affine", |b| b.iter(|| p1.to_affine()));

    let pp1 = p1.clone();
    let pp2 = p2.to_affine();
    group.bench_function("G1Projective and affine add", |b| b.iter(|| pp1 + pp2));

    let pp1 = p1.clone();
    let pp2 = p2.clone();
    group.bench_function("G1Projective and projective add", |b| b.iter(|| pp1 + pp2));

    let pp1 = p1.to_affine();
    let ss = s.clone();
    group.bench_function("G1Affine mul", |b| b.iter(|| pp1 * ss));

    let pp1 = p1.clone();
    let ss = s.clone();
    group.bench_function("G1Projective mul", |b| b.iter(|| pp1 * ss));

    group.bench_function("G2Projective into affine", |b| b.iter(|| h1.to_affine()));

    let hh1 = h1.clone();
    let hh2 = h2.to_affine();
    group.bench_function("G2Projective and affine add", |b| b.iter(|| hh1 + hh2));

    let hh1 = h1.clone();
    let hh2 = h2.clone();
    group.bench_function("G2Projective and projective add", |b| b.iter(|| hh1 + hh2));

    let hh1 = h1.to_affine();
    let ss = s.clone();
    group.bench_function("G2Affine mul", |b| b.iter(|| hh1 * ss));

    let hh1 = h1.clone();
    let ss = s.clone();
    group.bench_function("G2Projective mul", |b| b.iter(|| hh1 * ss));

    let hh1 = h1.to_affine();
    let pp1 = p1.to_affine();
    group.bench_function("G2 Pairing", |b| b.iter(|| pairing(&hh1, &pp1)));

    group.finish();
}

 */

pub fn blstrs_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("BLSTRS");
    group.sample_size(10);
    let size = 128usize;
    let xs: Vec<_> = (1..size).map(|_| Scalar::random(OsRng)).collect();
    let ys: Vec<_> = (1..size).map(|_| G1Projective::random(OsRng)).collect();
    let sys: Vec<_> = (1..size).map(|_| Scalar::random(OsRng)).collect();
    group.bench_function("crypto::interpolate Scalar", |b| b.iter(|| crypto::interpolate(&xs, sys.clone(), |s| s.invert().unwrap(), Scalar::zero())));
    //group.bench_function("crypto::interpolate_at Scalar", |b| b.iter(|| crypto::interpolate_at(&xs, sys.clone(), &Scalar::zero(), |s| s.invert().unwrap(), Scalar::zero())));
    //group.bench_function("crypto::interpolate_at", |b| b.iter(|| crypto::interpolate_at(&xs, ys.clone(), &Scalar::zero(), |s| s.invert().unwrap(), G1Projective::identity())));
    //group.bench_function("blstrs_lagrange", |b| b.iter(|| blstrs_lagrange_G1Projective(&xs, ys.clone(), &Scalar::zero())));
    group.finish();
}

criterion_group!(benches, blstrs_benchmark);
criterion_main!(benches);
