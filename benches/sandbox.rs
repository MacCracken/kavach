use criterion::{Criterion, criterion_group, criterion_main};
use kavach::backend::Backend;
use kavach::policy::SandboxPolicy;
use kavach::scoring;

fn bench_strength_scoring(c: &mut Criterion) {
    let policy = SandboxPolicy::strict();
    c.bench_function("score_backend_process_strict", |b| {
        b.iter(|| scoring::score_backend(Backend::Process, &policy))
    });
}

fn bench_backend_availability(c: &mut Criterion) {
    c.bench_function("backend_available_all", |b| b.iter(Backend::available));
}

fn bench_policy_creation(c: &mut Criterion) {
    c.bench_function("policy_strict_create", |b| b.iter(SandboxPolicy::strict));
}

criterion_group!(
    benches,
    bench_strength_scoring,
    bench_backend_availability,
    bench_policy_creation
);
criterion_main!(benches);
