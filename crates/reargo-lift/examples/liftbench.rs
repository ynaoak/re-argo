//! Microbenchmark of x86-64 lifting: `cargo run --release -p reargo-lift --example liftbench -- <elf>`.
//!
//! Lifts every instruction of `.text` (linearly) alone, through a
//! [`LiftCache`] in overlapping ranges as the analysis passes do, and
//! prints the time per instruction and the sizes of the lifted types.

use std::time::Instant;

use reargo_lift::x86::{LiftCache, X86Lifter};
use reargo_lift::{LiftedInstruction, PcodeLift};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "/usr/bin/python3.12".into());
    let info = reargo_loader::BinaryLoader::load(std::path::Path::new(&path)).expect("load");
    let text = info.sections.iter().find(|s| s.name == ".text").expect(".text");
    let mem = &info.memory;
    let fast = X86Lifter::new_64().without_parity();
    let mut addrs = Vec::new();
    let mut a = text.address;
    while a < text.address + text.size {
        match fast.lift_instruction(mem, a) {
            Ok(l) => {
                addrs.push(a);
                a += u64::from(l.length);
            }
            Err(_) => a += 1,
        }
    }
    let n = addrs.len();
    let ops: usize = addrs.iter().map(|&a| fast.lift_instruction(mem, a).map(|l| l.ops.len()).unwrap_or(0)).sum();
    let spare: usize =
        addrs.iter().map(|&a| fast.lift_instruction(mem, a).map(|l| l.ops.capacity() - l.ops.len()).unwrap_or(0)).sum();
    println!("spare op capacity {:.2}/insn", spare as f64 / addrs.len() as f64);
    println!(
        "{n} insns, {:.2} ops/insn; size_of PcodeOp {} LiftedInstruction {}",
        ops as f64 / n as f64,
        std::mem::size_of::<reargo_core::pcode::PcodeOp>(),
        std::mem::size_of::<LiftedInstruction>()
    );
    let reps: usize = std::env::var("REPS").ok().and_then(|r| r.parse().ok()).unwrap_or(5);
    let mut best = [f64::MAX; 4];
    for _ in 0..reps {
        // 1. lift each alone and drop it
        let t = Instant::now();
        let mut sink = 0usize;
        for &a in &addrs {
            if let Ok(l) = fast.lift_instruction(mem, a) {
                sink += l.ops.len();
            }
        }
        std::hint::black_box(sink);
        best[0] = best[0].min(t.elapsed().as_nanos() as f64 / n as f64);
        // 2. lift each alone, kept until the end
        let t = Instant::now();
        let kept: Vec<LiftedInstruction> = addrs.iter().filter_map(|&a| fast.lift_instruction(mem, a).ok()).collect();
        let el = t.elapsed().as_nanos() as f64 / n as f64;
        drop(kept);
        best[1] = best[1].min(el);
        // 3. overlapping ranges through a cache (a range of 300 from every 50th instruction)
        let t = Instant::now();
        let lifter = X86Lifter::new_64();
        let mut cache = LiftCache::new();
        let mut sink = 0usize;
        for chunk in addrs.chunks(50) {
            cache.trim(chunk[0], 4096);
            let r = lifter.lift_range_cached(mem, chunk[0], 300, &mut cache);
            sink += r.insns().len();
        }
        std::hint::black_box(sink);
        best[2] = best[2].min(t.elapsed().as_nanos() as f64 / n as f64);
        // 4. the same on 4 threads, each over a quarter
        let t = Instant::now();
        std::thread::scope(|sc| {
            for part in addrs.chunks(n.div_ceil(4)) {
                sc.spawn(move || {
                    let lifter = X86Lifter::new_64();
                    let mut cache = LiftCache::new();
                    let mut sink = 0usize;
                    for chunk in part.chunks(50) {
                        cache.trim(chunk[0], 4096);
                        let r = lifter.lift_range_cached(mem, chunk[0], 300, &mut cache);
                        sink += r.insns().iter().map(|l| l.ops.len()).sum::<usize>();
                    }
                    std::hint::black_box(sink);
                });
            }
        });
        best[3] = best[3].min(t.elapsed().as_nanos() as f64 * 4.0 / n as f64);
    }
    println!(
        "lift+drop {:.1} ns/insn; lift kept {:.1} ns/insn; cached ranges {:.1} ns/insn; 4 threads {:.1} ns/insn (cpu)",
        best[0], best[1], best[2], best[3]
    );
}
