// SARIF (Static Analysis Results Interchange Format) output.

use crate::Program;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Serialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    pub level: String,
}

#[derive(Debug, Serialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize)]
pub struct SarifPhysicalLocation {
    pub address: SarifAddress,
}

#[derive(Debug, Serialize)]
pub struct SarifAddress {
    #[serde(rename = "absoluteAddress")]
    pub absolute_address: u64,
}

pub fn generate_sarif(program: &Program) -> SarifReport {
    let mut results = Vec::new();

    for func in program.listing.functions() {
        if func.is_thunk {
            results.push(SarifResult {
                rule_id: "thunk-function".into(),
                message: SarifMessage { text: format!("Thunk function: {}", func.name) },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        address: SarifAddress { absolute_address: func.entry_point },
                    },
                }],
                level: "note".into(),
            });
        }
    }

    SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".into(),
        version: "2.1.0".into(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "ghidra-rust".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                },
            },
            results,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sarif_report_structure() {
        let report = SarifReport {
            schema: "test".into(),
            version: "2.1.0".into(),
            runs: vec![SarifRun {
                tool: SarifTool { driver: SarifDriver { name: "test".into(), version: "0.1".into() } },
                results: Vec::new(),
            }],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"version\":\"2.1.0\""));
        assert!(json.contains("\"$schema\":\"test\""));
    }
}
