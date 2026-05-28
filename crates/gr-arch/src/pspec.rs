use std::path::Path;

use quick_xml::events::Event;
use quick_xml::Reader;

#[derive(Debug, Clone)]
pub struct ProcessorSpec {
    pub program_counter: String,
    pub properties: Vec<(String, String)>,
    pub register_groups: Vec<RegisterGroup>,
    pub context_defaults: Vec<ContextDefault>,
}

#[derive(Debug, Clone)]
pub struct RegisterGroup {
    pub name: String,
    pub registers: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ContextDefault {
    pub name: String,
    pub value: u64,
    pub space: String,
}

#[derive(Debug, Clone)]
pub struct LanguageDef {
    pub processor: String,
    pub endian: String,
    pub size: u32,
    pub variant: String,
    pub id: String,
    pub sla_file: String,
    pub pspec_file: String,
    pub compilers: Vec<CompilerRef>,
}

#[derive(Debug, Clone)]
pub struct CompilerRef {
    pub name: String,
    pub spec_file: String,
    pub id: String,
}

#[derive(Debug, Default)]
pub struct LanguageDefFile {
    pub languages: Vec<LanguageDef>,
}

impl ProcessorSpec {
    pub fn parse_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("read {}: {}", path.display(), e))?;
        Self::parse_str(&content)
    }

    pub fn parse_str(xml: &str) -> Result<Self, String> {
        let mut reader = Reader::from_str(xml);
        let mut buf = Vec::new();
        let mut spec = ProcessorSpec {
            program_counter: String::new(),
            properties: Vec::new(),
            register_groups: Vec::new(),
            context_defaults: Vec::new(),
        };
        let mut in_properties = false;
        let mut in_register_data = false;
        let mut in_context_data = false;
        let mut current_group: Option<String> = None;
        let mut current_group_regs: Vec<String> = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                    let name = std::str::from_utf8(e.name().as_ref()).unwrap_or("").to_string();
                    match name.as_str() {
                        "properties" => in_properties = true,
                        "register_data" => in_register_data = true,
                        "context_data" | "context_set" | "tracked_set" => in_context_data = true,
                        "programcounter" => {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"register" {
                                    spec.program_counter = String::from_utf8_lossy(&attr.value).to_string();
                                }
                            }
                        }
                        "property" if in_properties => {
                            let mut key = String::new();
                            let mut val = String::new();
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"key" => key = String::from_utf8_lossy(&attr.value).to_string(),
                                    b"value" => val = String::from_utf8_lossy(&attr.value).to_string(),
                                    _ => {}
                                }
                            }
                            spec.properties.push((key, val));
                        }
                        "register" if in_register_data => {
                            let mut reg_name = String::new();
                            let mut group = String::new();
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"name" => reg_name = String::from_utf8_lossy(&attr.value).to_string(),
                                    b"group" => group = String::from_utf8_lossy(&attr.value).to_string(),
                                    _ => {}
                                }
                            }
                            if !group.is_empty() && !reg_name.is_empty() {
                                if current_group.as_deref() != Some(&group) {
                                    if let Some(g) = current_group.take() {
                                        spec.register_groups.push(RegisterGroup {
                                            name: g,
                                            registers: std::mem::take(&mut current_group_regs),
                                        });
                                    }
                                    current_group = Some(group);
                                }
                                current_group_regs.push(reg_name);
                            }
                        }
                        "set" if in_context_data => {
                            let mut ctx_name = String::new();
                            let mut ctx_val = 0u64;
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"name" => ctx_name = String::from_utf8_lossy(&attr.value).to_string(),
                                    b"val" => {
                                        let s = String::from_utf8_lossy(&attr.value);
                                        ctx_val = s.parse().unwrap_or(0);
                                    }
                                    _ => {}
                                }
                            }
                            if !ctx_name.is_empty() {
                                spec.context_defaults.push(ContextDefault {
                                    name: ctx_name,
                                    value: ctx_val,
                                    space: "ram".into(),
                                });
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(e)) => {
                    let name_bytes = e.name().as_ref().to_vec();
                    let name = std::str::from_utf8(&name_bytes).unwrap_or("");
                    match name {
                        "properties" => in_properties = false,
                        "register_data" => {
                            in_register_data = false;
                            if let Some(g) = current_group.take() {
                                spec.register_groups.push(RegisterGroup {
                                    name: g,
                                    registers: std::mem::take(&mut current_group_regs),
                                });
                            }
                        }
                        "context_data" => in_context_data = false,
                        _ => {}
                    }
                }
                Err(e) => return Err(format!("XML: {}", e)),
                _ => {}
            }
            buf.clear();
        }
        Ok(spec)
    }
}

impl LanguageDefFile {
    pub fn parse_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("read {}: {}", path.display(), e))?;
        Self::parse_str(&content)
    }

    pub fn parse_str(xml: &str) -> Result<Self, String> {
        let mut reader = Reader::from_str(xml);
        let mut buf = Vec::new();
        let mut file = LanguageDefFile::default();
        let mut in_language = false;
        let mut current_lang = LanguageDef {
            processor: String::new(), endian: String::new(), size: 0,
            variant: String::new(), id: String::new(),
            sla_file: String::new(), pspec_file: String::new(),
            compilers: Vec::new(),
        };

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                    let name = std::str::from_utf8(e.name().as_ref()).unwrap_or("").to_string();
                    match name.as_str() {
                        "language" => {
                            in_language = true;
                            current_lang = LanguageDef {
                                processor: String::new(), endian: String::new(), size: 0,
                                variant: String::new(), id: String::new(),
                                sla_file: String::new(), pspec_file: String::new(),
                                compilers: Vec::new(),
                            };
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"processor" => current_lang.processor = String::from_utf8_lossy(&attr.value).to_string(),
                                    b"endian" => current_lang.endian = String::from_utf8_lossy(&attr.value).to_string(),
                                    b"size" => current_lang.size = String::from_utf8_lossy(&attr.value).parse().unwrap_or(0),
                                    b"variant" => current_lang.variant = String::from_utf8_lossy(&attr.value).to_string(),
                                    b"id" => current_lang.id = String::from_utf8_lossy(&attr.value).to_string(),
                                    b"slafile" => current_lang.sla_file = String::from_utf8_lossy(&attr.value).to_string(),
                                    b"processorspec" => current_lang.pspec_file = String::from_utf8_lossy(&attr.value).to_string(),
                                    _ => {}
                                }
                            }
                        }
                        "compiler" if in_language => {
                            let mut comp = CompilerRef { name: String::new(), spec_file: String::new(), id: String::new() };
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"name" => comp.name = String::from_utf8_lossy(&attr.value).to_string(),
                                    b"spec" => comp.spec_file = String::from_utf8_lossy(&attr.value).to_string(),
                                    b"id" => comp.id = String::from_utf8_lossy(&attr.value).to_string(),
                                    _ => {}
                                }
                            }
                            current_lang.compilers.push(comp);
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(e))
                    if std::str::from_utf8(e.name().as_ref()).unwrap_or("") == "language" => {
                        in_language = false;
                        file.languages.push(current_lang.clone());
                    }
                Err(e) => return Err(format!("XML: {}", e)),
                _ => {}
            }
            buf.clear();
        }
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pspec() {
        let xml = r#"<?xml version="1.0"?>
<processor_spec>
  <programcounter register="PC"/>
  <properties>
    <property key="test" value="true"/>
  </properties>
  <register_data>
    <register name="DR0" group="DEBUG"/>
    <register name="DR1" group="DEBUG"/>
    <register name="CR0" group="CONTROL"/>
  </register_data>
  <context_data>
    <context_set space="ram">
      <set name="mode" val="1"/>
    </context_set>
  </context_data>
</processor_spec>"#;
        let spec = ProcessorSpec::parse_str(xml).unwrap();
        assert_eq!(spec.program_counter, "PC");
        assert_eq!(spec.properties.len(), 1);
        assert_eq!(spec.register_groups.len(), 2);
        assert_eq!(spec.register_groups[0].name, "DEBUG");
        assert_eq!(spec.register_groups[0].registers.len(), 2);
        assert_eq!(spec.context_defaults.len(), 1);
        assert_eq!(spec.context_defaults[0].name, "mode");
    }

    #[test]
    fn parse_ldefs() {
        let xml = r#"<?xml version="1.0"?>
<language_definitions>
  <language processor="x86" endian="little" size="64" variant="default"
            id="x86:LE:64:default" slafile="x86-64.sla" processorspec="x86-64.pspec">
    <compiler name="gcc" spec="x86-64-gcc.cspec" id="gcc"/>
    <compiler name="Visual Studio" spec="x86-64-win.cspec" id="windows"/>
  </language>
</language_definitions>"#;
        let file = LanguageDefFile::parse_str(xml).unwrap();
        assert_eq!(file.languages.len(), 1);
        let lang = &file.languages[0];
        assert_eq!(lang.processor, "x86");
        assert_eq!(lang.size, 64);
        assert_eq!(lang.compilers.len(), 2);
        assert_eq!(lang.compilers[0].name, "gcc");
    }
}
