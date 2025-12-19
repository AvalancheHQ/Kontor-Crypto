//! CodSpeed benchmarks for Kontor PoR
//!
//! These benchmarks are compatible with both criterion and CodSpeed.
//! Run locally with: cargo bench
//! Run with CodSpeed: cargo codspeed run

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kontor_crypto::{
    api::{self, Challenge, FieldElement, PorSystem},
    build_tree, config, get_padded_proof_for_leaf,
    poseidon::{domain_tags, poseidon_hash_tagged},
    FileLedger,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::collections::BTreeMap;

// Helper function to generate test data
fn generate_test_data(size: usize) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(config::BENCHMARK_SEED);
    let mut data = vec![0u8; size];
    rng.fill_bytes(&mut data);
    data
}

// Microbenchmarks
fn bench_poseidon_hash(c: &mut Criterion) {
    let a = FieldElement::from(config::TEST_RANDOM_SEED);
    let b = FieldElement::from(123u64);
    
    c.bench_function("poseidon_hash_domain_separated", |bench| {
        bench.iter(|| {
            black_box(poseidon_hash_tagged(
                domain_tags::node(),
                black_box(a),
                black_box(b),
            ))
        });
    });
}

fn bench_tree_building(c: &mut Criterion) {
    let num_leaves = config::BENCHMARK_TREE_LEAVES;
    let data: Vec<Vec<u8>> = (0..num_leaves)
        .map(|i| format!("leaf_{}", i).into_bytes())
        .collect();

    c.bench_function("build_tree_256_leaves", |bench| {
        bench.iter(|| {
            black_box(build_tree(black_box(&data)).unwrap())
        });
    });
}

fn bench_merkle_proof(c: &mut Criterion) {
    let num_leaves = config::BENCHMARK_TREE_LEAVES;
    let data: Vec<Vec<u8>> = (0..num_leaves)
        .map(|i| format!("leaf_{}", i).into_bytes())
        .collect();
    let (tree, _root) = build_tree(&data).unwrap();

    c.bench_function("generate_merkle_proof", |bench| {
        bench.iter(|| {
            black_box(get_padded_proof_for_leaf(
                black_box(&tree),
                black_box(config::BENCHMARK_PROOF_LEAF_INDEX),
                black_box(config::BENCHMARK_TREE_DEPTH),
            ))
        });
    });
}

// Setup benchmarks
fn bench_prepare_file_small(c: &mut Criterion) {
    let data = generate_test_data(config::BENCHMARK_FILE_SIZE_SMALL * 1024);
    
    c.bench_function("prepare_file_16kb", |bench| {
        bench.iter(|| {
            black_box(api::prepare_file(black_box(&data), "test_file.dat").unwrap())
        });
    });
}

fn bench_prepare_file_medium(c: &mut Criterion) {
    let data = generate_test_data(config::BENCHMARK_FILE_SIZE_MEDIUM * 1024);
    
    c.bench_function("prepare_file_32kb", |bench| {
        bench.iter(|| {
            black_box(api::prepare_file(black_box(&data), "test_file.dat").unwrap())
        });
    });
}

// Proving benchmarks
fn bench_prove_small_2_challenges(c: &mut Criterion) {
    let data = generate_test_data(config::BENCHMARK_FILE_SIZE_SMALL * 1024);
    let (prepared_file, metadata) = api::prepare_file(&data, "bench_test.dat").unwrap();
    
    let seed = FieldElement::from(config::TEST_RANDOM_SEED);
    let challenge = Challenge::new(
        metadata.clone(),
        1000,
        2,
        seed,
        String::from("bench_prover"),
    );
    
    let mut ledger = FileLedger::new();
    ledger.add_file(&metadata).unwrap();
    let system = PorSystem::new(&ledger);
    let challenges = vec![challenge];

    c.bench_function("prove_16kb_2_challenges", |bench| {
        bench.iter(|| {
            black_box(system.prove(
                black_box(vec![&prepared_file]),
                black_box(&challenges),
            ).unwrap())
        });
    });
}

fn bench_prove_medium_3_challenges(c: &mut Criterion) {
    let data = generate_test_data(config::BENCHMARK_FILE_SIZE_MEDIUM * 1024);
    let (prepared_file, metadata) = api::prepare_file(&data, "bench_test.dat").unwrap();
    
    let seed = FieldElement::from(config::TEST_RANDOM_SEED);
    let challenge = Challenge::new(
        metadata.clone(),
        1000,
        3,
        seed,
        String::from("bench_prover"),
    );
    
    let mut ledger = FileLedger::new();
    ledger.add_file(&metadata).unwrap();
    let system = PorSystem::new(&ledger);
    let challenges = vec![challenge];

    c.bench_function("prove_32kb_3_challenges", |bench| {
        bench.iter(|| {
            black_box(system.prove(
                black_box(vec![&prepared_file]),
                black_box(&challenges),
            ).unwrap())
        });
    });
}

fn bench_prove_small_5_challenges(c: &mut Criterion) {
    let data = generate_test_data(config::BENCHMARK_FILE_SIZE_SMALL * 1024);
    let (prepared_file, metadata) = api::prepare_file(&data, "bench_test.dat").unwrap();
    
    let seed = FieldElement::from(config::TEST_RANDOM_SEED);
    let challenge = Challenge::new(
        metadata.clone(),
        1000,
        5,
        seed,
        String::from("bench_prover"),
    );
    
    let mut ledger = FileLedger::new();
    ledger.add_file(&metadata).unwrap();
    let system = PorSystem::new(&ledger);
    let challenges = vec![challenge];

    c.bench_function("prove_16kb_5_challenges", |bench| {
        bench.iter(|| {
            black_box(system.prove(
                black_box(vec![&prepared_file]),
                black_box(&challenges),
            ).unwrap())
        });
    });
}

// Verification benchmark
fn bench_verify(c: &mut Criterion) {
    let data = generate_test_data(config::BENCHMARK_FILE_SIZE_SMALL * 1024);
    let (prepared_file, metadata) = api::prepare_file(&data, "bench_test.dat").unwrap();
    
    let seed = FieldElement::from(config::TEST_RANDOM_SEED);
    let challenge = Challenge::new(
        metadata.clone(),
        1000,
        2,
        seed,
        String::from("bench_prover"),
    );
    
    let mut ledger = FileLedger::new();
    ledger.add_file(&metadata).unwrap();
    let system = PorSystem::new(&ledger);
    let challenges = vec![challenge.clone()];
    let proof = system.prove(vec![&prepared_file], &challenges).unwrap();

    c.bench_function("verify_proof", |bench| {
        bench.iter(|| {
            black_box(system.verify(
                black_box(&proof),
                black_box(&challenges),
            ).unwrap())
        });
    });
}

// End-to-end workflow
fn bench_e2e_workflow(c: &mut Criterion) {
    c.bench_function("e2e_workflow_16kb_2_challenges", |bench| {
        bench.iter(|| {
            // Generate data
            let data = black_box(generate_test_data(config::BENCHMARK_FILE_SIZE_SMALL * 1024));
            
            // Prepare file
            let (prepared_file, metadata) = black_box(
                api::prepare_file(&data, "e2e_test.dat").unwrap()
            );
            
            // Create challenge
            let seed = FieldElement::from(42u64);
            let challenge = black_box(Challenge::new(
                metadata.clone(),
                1000,
                2,
                seed,
                String::from("bench_prover"),
            ));
            
            // Create ledger and system
            let mut ledger = FileLedger::new();
            ledger.add_file(&metadata).unwrap();
            let system = PorSystem::new(&ledger);
            let challenges = vec![challenge.clone()];
            
            // Prove
            let proof = black_box(system.prove(vec![&prepared_file], &challenges).unwrap());
            
            // Verify
            black_box(system.verify(&proof, &challenges).unwrap())
        });
    });
}

criterion_group!(
    microbenchmarks,
    bench_poseidon_hash,
    bench_tree_building,
    bench_merkle_proof,
);

criterion_group!(
    setup_benchmarks,
    bench_prepare_file_small,
    bench_prepare_file_medium,
);

criterion_group!(
    proving_benchmarks,
    bench_prove_small_2_challenges,
    bench_prove_medium_3_challenges,
    bench_prove_small_5_challenges,
);

criterion_group!(
    verification_benchmarks,
    bench_verify,
);

criterion_group!(
    e2e_benchmarks,
    bench_e2e_workflow,
);

criterion_main!(
    microbenchmarks,
    setup_benchmarks,
    proving_benchmarks,
    verification_benchmarks,
    e2e_benchmarks,
);
