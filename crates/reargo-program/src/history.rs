// Analysis history tracking.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisEvent {
    pub analyzer: String,
    pub timestamp_ms: u64,
    pub functions_found: usize,
    pub references_found: usize,
    pub duration_ms: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AnalysisHistory {
    events: Vec<AnalysisEvent>,
}

impl AnalysisHistory {
    pub fn new() -> Self { Self::default() }

    pub fn record(&mut self, event: AnalysisEvent) {
        self.events.push(event);
    }

    pub fn events(&self) -> &[AnalysisEvent] { &self.events }

    pub fn total_functions_found(&self) -> usize {
        self.events.iter().map(|e| e.functions_found).sum()
    }

    pub fn total_references_found(&self) -> usize {
        self.events.iter().map(|e| e.references_found).sum()
    }

    pub fn total_duration_ms(&self) -> u64 {
        self.events.iter().map(|e| e.duration_ms).sum()
    }

    pub fn analyzer_names(&self) -> Vec<&str> {
        self.events.iter().map(|e| e.analyzer.as_str()).collect()
    }

    pub fn len(&self) -> usize { self.events.len() }
    pub fn is_empty(&self) -> bool { self.events.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_tracking() {
        let mut history = AnalysisHistory::new();
        history.record(AnalysisEvent {
            analyzer: "FunctionDiscovery".into(),
            timestamp_ms: 1000,
            functions_found: 50,
            references_found: 200,
            duration_ms: 150,
        });
        history.record(AnalysisEvent {
            analyzer: "StringSearch".into(),
            timestamp_ms: 1150,
            functions_found: 0,
            references_found: 0,
            duration_ms: 50,
        });
        assert_eq!(history.len(), 2);
        assert_eq!(history.total_functions_found(), 50);
        assert_eq!(history.total_duration_ms(), 200);
    }
}
