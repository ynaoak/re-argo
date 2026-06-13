use crate::Program;

pub fn export_ghidra_xml(program: &Program) -> String {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<PROGRAM NAME=\"");
    xml.push_str(&escape_xml(&program.name));
    xml.push_str("\">\n");

    xml.push_str("  <INFO_SOURCE>\n");
    xml.push_str(&format!("    <FORMAT>{}</FORMAT>\n", program.info.format));
    xml.push_str(&format!("    <ARCHITECTURE>{}</ARCHITECTURE>\n", program.info.arch));
    xml.push_str(&format!("    <BITS>{}</BITS>\n", program.info.bits));
    xml.push_str(&format!("    <ENTRY_POINT>0x{:x}</ENTRY_POINT>\n", program.entry_point()));
    xml.push_str("  </INFO_SOURCE>\n");

    xml.push_str("  <FUNCTIONS>\n");
    for func in program.listing.functions() {
        xml.push_str(&format!(
            "    <FUNCTION NAME=\"{}\" ENTRY=\"0x{:x}\" BLOCKS=\"{}\"",
            escape_xml(&func.name), func.entry_point, func.body.len()
        ));
        if func.is_thunk
            && let Some(target) = func.thunk_target {
                xml.push_str(&format!(" THUNK=\"0x{:x}\"", target));
            }
        xml.push_str(" />\n");
    }
    xml.push_str("  </FUNCTIONS>\n");

    xml.push_str("  <SYMBOLS>\n");
    for sym in program.symbol_table.iter().take(5000) {
        xml.push_str(&format!(
            "    <SYMBOL NAME=\"{}\" ADDRESS=\"0x{:x}\" TYPE=\"{:?}\" />\n",
            escape_xml(&sym.name), sym.address, sym.symbol_type
        ));
    }
    xml.push_str("  </SYMBOLS>\n");

    xml.push_str("  <REFERENCES>\n");
    for r in program.references.all_refs().take(10000) {
        xml.push_str(&format!(
            "    <REF FROM=\"0x{:x}\" TO=\"0x{:x}\" TYPE=\"{}\" />\n",
            r.from, r.to, r.ref_type
        ));
    }
    xml.push_str("  </REFERENCES>\n");

    xml.push_str("</PROGRAM>\n");
    xml
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_xml_chars() {
        assert_eq!(escape_xml("a<b>c&d\"e"), "a&lt;b&gt;c&amp;d&quot;e");
    }
}
