use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_euclidean_distance(c: &mut Criterion) {
    let a: Vec<f32> = (0..128).map(|i| i as f32 / 128.0).collect();
    let b: Vec<f32> = (0..128).map(|i| (i as f32 / 128.0) + 0.1).collect();
    c.bench_function("euclidean_distance_128", |bench| {
        bench.iter(|| {
            let sum: f32 = black_box(&a)
                .iter()
                .zip(black_box(&b).iter())
                .map(|(x, y)| (x - y).powi(2))
                .sum();
            black_box(sum.sqrt())
        });
    });
}

fn bench_calculate_score(c: &mut Criterion) {
    c.bench_function("calculate_score", |bench| {
        bench.iter(|| {
            let raw: f32 = (1.0 - black_box(0.5) / black_box(1.0)) * 100.0;
            black_box(raw.clamp(0.0, 100.0) as u8)
        });
    });
}

fn bench_quality_gate_two_modalities(c: &mut Criterion) {
    use hus_sdk::config::ModalityConfig;
    use hus_sdk::quality_gate::QualityGate;
    let cfgs = vec![
        ModalityConfig::for_modality(hus_sdk::config::Modality::Face),
        ModalityConfig::for_modality(hus_sdk::config::Modality::Iris),
    ];
    let gate = QualityGate::new(cfgs);
    c.bench_function("quality_gate_two_modalities", |bench| {
        bench.iter(|| black_box(gate.assess(black_box(&[true, true]))));
    });
}

criterion_group!(
    benches,
    bench_euclidean_distance,
    bench_calculate_score,
    bench_quality_gate_two_modalities
);
criterion_main!(benches);
