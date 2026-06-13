use std::path::Path;

use quick_xml::events::Event;
use quick_xml::Reader;

#[derive(Debug, Clone)]
pub struct CompilerSpec {
    pub name: String,
    pub stack_pointer: String,
    pub pointer_size: u32,
    pub default_proto: PrototypeSpec,
    pub additional_protos: Vec<PrototypeSpec>,
    pub data_org: DataOrganization,
}

#[derive(Debug, Clone)]
pub struct PrototypeSpec {
    pub name: String,
    pub extrapop: u32,
    pub stackshift: u32,
    pub input_params: Vec<ParamEntry>,
    pub output_params: Vec<ParamEntry>,
    pub killed_by_call: Vec<String>,
    pub unaffected: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParamEntry {
    pub register: Option<String>,
    pub min_size: u32,
    pub max_size: u32,
    pub metatype: Option<String>,
    pub stack_offset: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct DataOrganization {
    pub pointer_size: u32,
    pub short_size: u32,
    pub integer_size: u32,
    pub long_size: u32,
    pub long_long_size: u32,
    pub float_size: u32,
    pub double_size: u32,
    pub wchar_size: u32,
}

impl CompilerSpec {
    pub fn parse_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
        Self::parse_str(&content)
    }

    pub fn parse_str(xml: &str) -> Result<Self, String> {
        let mut reader = Reader::from_str(xml);

        let mut spec = CompilerSpec {
            name: String::new(),
            stack_pointer: String::new(),
            pointer_size: 8,
            default_proto: PrototypeSpec::empty(),
            additional_protos: Vec::new(),
            data_org: DataOrganization::default(),
        };

        let mut buf = Vec::new();
        let mut in_default_proto = false;
        let mut in_proto: Option<String> = None;
        let mut in_input = false;
        let mut in_output = false;
        let mut in_killed = false;
        let mut in_unaffected = false;
        let mut in_data_org = false;
        let mut current_proto = PrototypeSpec::empty();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                    let name = std::str::from_utf8(e.name().as_ref())
                        .unwrap_or("")
                        .to_string();

                    match name.as_str() {
                        "stackpointer" => {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"register" {
                                    spec.stack_pointer = String::from_utf8_lossy(&attr.value).to_string();
                                }
                            }
                        }
                        "data_organization" => {
                            in_data_org = true;
                        }
                        "pointer_size" if in_data_org => {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"value" {
                                    spec.data_org.pointer_size = parse_u32(&attr.value);
                                    spec.pointer_size = spec.data_org.pointer_size;
                                }
                            }
                        }
                        "short_size" if in_data_org => {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"value" {
                                    spec.data_org.short_size = parse_u32(&attr.value);
                                }
                            }
                        }
                        "integer_size" if in_data_org => {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"value" {
                                    spec.data_org.integer_size = parse_u32(&attr.value);
                                }
                            }
                        }
                        "long_size" if in_data_org => {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"value" {
                                    spec.data_org.long_size = parse_u32(&attr.value);
                                }
                            }
                        }
                        "long_long_size" if in_data_org => {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"value" {
                                    spec.data_org.long_long_size = parse_u32(&attr.value);
                                }
                            }
                        }
                        "float_size" if in_data_org => {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"value" {
                                    spec.data_org.float_size = parse_u32(&attr.value);
                                }
                            }
                        }
                        "double_size" if in_data_org => {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"value" {
                                    spec.data_org.double_size = parse_u32(&attr.value);
                                }
                            }
                        }
                        "wchar_size" if in_data_org => {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"value" {
                                    spec.data_org.wchar_size = parse_u32(&attr.value);
                                }
                            }
                        }
                        "default_proto" => {
                            in_default_proto = true;
                        }
                        "prototype" => {
                            let mut proto_name = String::new();
                            let mut extrapop = 0u32;
                            let mut stackshift = 0u32;
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"name" => proto_name = String::from_utf8_lossy(&attr.value).to_string(),
                                    b"extrapop" => extrapop = parse_u32(&attr.value),
                                    b"stackshift" => stackshift = parse_u32(&attr.value),
                                    _ => {}
                                }
                            }
                            current_proto = PrototypeSpec {
                                name: proto_name.clone(),
                                extrapop,
                                stackshift,
                                input_params: Vec::new(),
                                output_params: Vec::new(),
                                killed_by_call: Vec::new(),
                                unaffected: Vec::new(),
                            };
                            in_proto = Some(proto_name);
                        }
                        "input" if in_proto.is_some() => {
                            in_input = true;
                        }
                        "output" if in_proto.is_some() => {
                            in_output = true;
                        }
                        "killedbycall" if in_proto.is_some() => {
                            in_killed = true;
                        }
                        "unaffected" if in_proto.is_some() => {
                            in_unaffected = true;
                        }
                        "pentry" if in_input || in_output => {
                            let mut entry = ParamEntry {
                                register: None,
                                min_size: 1,
                                max_size: 8,
                                metatype: None,
                                stack_offset: None,
                            };
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"minsize" => entry.min_size = parse_u32(&attr.value),
                                    b"maxsize" => entry.max_size = parse_u32(&attr.value),
                                    b"metatype" => entry.metatype = Some(String::from_utf8_lossy(&attr.value).to_string()),
                                    _ => {}
                                }
                            }
                            if in_input {
                                current_proto.input_params.push(entry);
                            } else {
                                current_proto.output_params.push(entry);
                            }
                        }
                        "register" if in_input || in_output => {
                            let mut reg_name = String::new();
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"name" {
                                    reg_name = String::from_utf8_lossy(&attr.value).to_string();
                                }
                            }
                            if let Some(last) = if in_input {
                                current_proto.input_params.last_mut()
                            } else {
                                current_proto.output_params.last_mut()
                            } {
                                last.register = Some(reg_name);
                            }
                        }
                        "register" if in_killed => {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"name" {
                                    current_proto.killed_by_call.push(
                                        String::from_utf8_lossy(&attr.value).to_string(),
                                    );
                                }
                            }
                        }
                        "register" if in_unaffected => {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"name" {
                                    current_proto.unaffected.push(
                                        String::from_utf8_lossy(&attr.value).to_string(),
                                    );
                                }
                            }
                        }
                        "addr" if in_input || in_output => {
                            let mut offset: Option<i64> = None;
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"offset" {
                                    offset = Some(parse_u32(&attr.value) as i64);
                                }
                            }
                            if let Some(last) = if in_input {
                                current_proto.input_params.last_mut()
                            } else {
                                current_proto.output_params.last_mut()
                            } {
                                last.stack_offset = offset;
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(e)) => {
                    let name = std::str::from_utf8(e.name().as_ref())
                        .unwrap_or("")
                        .to_string();
                    match name.as_str() {
                        "data_organization" => in_data_org = false,
                        "default_proto" => in_default_proto = false,
                        "prototype" => {
                            if in_default_proto {
                                spec.default_proto = current_proto.clone();
                                spec.name = current_proto.name.clone();
                            } else {
                                spec.additional_protos.push(current_proto.clone());
                            }
                            in_proto = None;
                        }
                        "input" => in_input = false,
                        "output" => in_output = false,
                        "killedbycall" => in_killed = false,
                        "unaffected" => in_unaffected = false,
                        _ => {}
                    }
                }
                Err(e) => return Err(format!("XML parse error: {}", e)),
                _ => {}
            }
            buf.clear();
        }

        Ok(spec)
    }

    pub fn integer_param_registers(&self) -> Vec<&str> {
        self.default_proto
            .input_params
            .iter()
            .filter(|p| p.metatype.as_deref() != Some("float"))
            .filter_map(|p| p.register.as_deref())
            .collect()
    }

    pub fn return_register(&self) -> Option<&str> {
        self.default_proto
            .output_params
            .iter()
            .filter(|p| p.metatype.as_deref() != Some("float"))
            .find_map(|p| p.register.as_deref())
    }
}

impl PrototypeSpec {
    fn empty() -> Self {
        Self {
            name: String::new(),
            extrapop: 0,
            stackshift: 0,
            input_params: Vec::new(),
            output_params: Vec::new(),
            killed_by_call: Vec::new(),
            unaffected: Vec::new(),
        }
    }
}

fn parse_u32(val: &[u8]) -> u32 {
    let s = std::str::from_utf8(val).unwrap_or("0");
    s.parse().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSV_CSPEC: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<compiler_spec>
  <data_organization>
    <pointer_size value="8" />
    <integer_size value="4" />
    <long_size value="8" />
  </data_organization>
  <stackpointer register="RSP" space="ram"/>
  <default_proto>
    <prototype name="__stdcall" extrapop="8" stackshift="8">
      <input>
        <pentry minsize="1" maxsize="8">
          <register name="RDI"/>
        </pentry>
        <pentry minsize="1" maxsize="8">
          <register name="RSI"/>
        </pentry>
        <pentry minsize="1" maxsize="8">
          <register name="RDX"/>
        </pentry>
        <pentry minsize="1" maxsize="8">
          <register name="RCX"/>
        </pentry>
        <pentry minsize="1" maxsize="8">
          <register name="R8"/>
        </pentry>
        <pentry minsize="1" maxsize="8">
          <register name="R9"/>
        </pentry>
      </input>
      <output>
        <pentry minsize="1" maxsize="8">
          <register name="RAX"/>
        </pentry>
      </output>
      <killedbycall>
        <register name="RAX"/>
        <register name="RDX"/>
      </killedbycall>
      <unaffected>
        <register name="RBX"/>
        <register name="RSP"/>
        <register name="RBP"/>
        <register name="R12"/>
        <register name="R13"/>
        <register name="R14"/>
        <register name="R15"/>
      </unaffected>
    </prototype>
  </default_proto>
</compiler_spec>"#;

    const WIN_CSPEC: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<compiler_spec>
  <data_organization>
    <pointer_size value="8" />
    <long_size value="4" />
  </data_organization>
  <stackpointer register="RSP" space="ram"/>
  <default_proto>
    <prototype name="__fastcall" extrapop="8" stackshift="8">
      <input>
        <pentry minsize="1" maxsize="8">
          <register name="RCX"/>
        </pentry>
        <pentry minsize="1" maxsize="8">
          <register name="RDX"/>
        </pentry>
        <pentry minsize="1" maxsize="8">
          <register name="R8"/>
        </pentry>
        <pentry minsize="1" maxsize="8">
          <register name="R9"/>
        </pentry>
      </input>
      <output>
        <pentry minsize="1" maxsize="8">
          <register name="RAX"/>
        </pentry>
      </output>
      <unaffected>
        <register name="RBX"/>
        <register name="RBP"/>
        <register name="RSP"/>
        <register name="R12"/>
        <register name="R13"/>
        <register name="R14"/>
        <register name="R15"/>
      </unaffected>
    </prototype>
  </default_proto>
</compiler_spec>"#;

    #[test]
    fn parse_sysv_cspec() {
        let spec = CompilerSpec::parse_str(SYSV_CSPEC).unwrap();
        assert_eq!(spec.stack_pointer, "RSP");
        assert_eq!(spec.pointer_size, 8);
        assert_eq!(spec.default_proto.name, "__stdcall");
        let int_params = spec.integer_param_registers();
        assert_eq!(int_params, vec!["RDI", "RSI", "RDX", "RCX", "R8", "R9"]);
        assert_eq!(spec.return_register(), Some("RAX"));
        assert!(spec.default_proto.unaffected.contains(&"RBX".to_string()));
        assert!(spec.default_proto.killed_by_call.contains(&"RAX".to_string()));
    }

    #[test]
    fn parse_win_cspec() {
        let spec = CompilerSpec::parse_str(WIN_CSPEC).unwrap();
        assert_eq!(spec.default_proto.name, "__fastcall");
        let int_params = spec.integer_param_registers();
        assert_eq!(int_params, vec!["RCX", "RDX", "R8", "R9"]);
        assert_eq!(spec.data_org.long_size, 4);
    }

    #[test]
    fn parse_real_sysv_file() {
        let path = Path::new("ghidra/Ghidra/Processors/x86/data/languages/x86-64-gcc.cspec");
        if !path.exists() {
            return;
        }
        let spec = CompilerSpec::parse_file(path).unwrap();
        assert_eq!(spec.stack_pointer, "RSP");
        assert!(!spec.default_proto.input_params.is_empty());
    }
}
