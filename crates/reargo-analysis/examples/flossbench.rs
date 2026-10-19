//! `cargo run --release -p reargo-analysis --example flossbench -- <bin> [iters]`:
//! FLOSS-lite on a binary's sections with the pipeline's options.
use reargo_analysis::floss_lite::{decode_section, FlossOptions};
use reargo_loader::SectionFlags;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let info = reargo_loader::BinaryLoader::load(std::path::Path::new(&args[1])).expect("load");
    let iters: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
    let sections: Vec<(u64, Vec<u8>)> = info
        .sections
        .iter()
        .filter(|s| s.size > 0 && s.size <= 16 * 1024 * 1024 && !s.flags.contains(SectionFlags::EXECUTE))
        .filter_map(|s| {
            let mut buf = vec![0u8; s.size as usize];
            info.memory.read_bytes(s.address, &mut buf).ok()?;
            Some((s.address, buf))
        })
        .collect();
    let opts = FlossOptions { min_length: 12, ..FlossOptions::default() };
    let t = std::time::Instant::now();
    let mut total = 0;
    for _ in 0..iters {
        total = sections.iter().map(|(a, b)| decode_section(b, *a, &opts).len()).sum::<usize>();
    }
    if std::env::var("RAW").is_ok() {
        for (a, b) in &sections {
            let raw = decode_section(b, *a, &FlossOptions { max_per_section: usize::MAX / 2, dedup_per_address: false, ..opts });
            println!("{:#x} len {} raw {}", a, b.len(), raw.len());
        }
    }
    println!("{} strings, {:.1} ms/iter", total, t.elapsed().as_secs_f64() * 1000.0 / iters as f64);
}
