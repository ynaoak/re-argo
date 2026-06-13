// SLEIGH specification compiler interface.
// Manages .slaspec -> .sla compilation pipeline.

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct SleighSpec {
    pub processor: String,
    pub endian: String,
    pub size: u32,
    pub sla_file: PathBuf,
    pub pspec_file: PathBuf,
    pub cspec_files: Vec<PathBuf>,
}

#[derive(Debug)]
pub struct SleighCompilerConfig {
    pub ghidra_root: PathBuf,
    pub output_dir: PathBuf,
    pub verbose: bool,
}

impl SleighCompilerConfig {
    pub fn new(ghidra_root: impl Into<PathBuf>) -> Self {
        let root: PathBuf = ghidra_root.into();
        Self {
            output_dir: root.join("compiled"),
            ghidra_root: root,
            verbose: false,
        }
    }

    pub fn processor_dir(&self, processor: &str) -> PathBuf {
        self.ghidra_root.join("Ghidra").join("Processors").join(processor)
    }

    pub fn languages_dir(&self, processor: &str) -> PathBuf {
        self.processor_dir(processor).join("data").join("languages")
    }

    pub fn list_processors(&self) -> Vec<String> {
        let proc_dir = self.ghidra_root.join("Ghidra").join("Processors");
        if !proc_dir.exists() { return Vec::new(); }
        let mut procs = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&proc_dir) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|t| t.is_dir())
                    && let Some(name) = entry.file_name().to_str() {
                        procs.push(name.to_string());
                    }
            }
        }
        procs.sort();
        procs
    }

    pub fn find_specs(&self, processor: &str) -> Vec<SleighSpec> {
        let lang_dir = self.languages_dir(processor);
        if !lang_dir.exists() { return Vec::new(); }
        let mut specs = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&lang_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "sla") {
                    specs.push(SleighSpec {
                        processor: processor.into(),
                        endian: "little".into(),
                        size: 0,
                        sla_file: path,
                        pspec_file: PathBuf::new(),
                        cspec_files: Vec::new(),
                    });
                }
            }
        }
        specs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiler_config() {
        let config = SleighCompilerConfig::new("ghidra");
        let dir = config.languages_dir("x86");
        assert!(dir.to_string_lossy().contains("x86"));
    }

    #[test]
    fn list_processors() {
        let config = SleighCompilerConfig::new("ghidra");
        let procs = config.list_processors();
        // May or may not have processors depending on submodule
        assert!(procs.is_empty() || procs.contains(&"x86".to_string()));
    }
}
