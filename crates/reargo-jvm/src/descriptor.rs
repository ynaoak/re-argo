//! Field / method descriptor pretty-printing (`(Ljava/lang/String;I)V`
//! → `void (java.lang.String, int)`).

/// Java source form of one field type, consuming it from `s`.
fn parse_type(s: &mut &str) -> Option<String> {
    let mut dims = 0;
    while let Some(rest) = s.strip_prefix('[') {
        dims += 1;
        *s = rest;
    }
    let c = s.chars().next()?;
    *s = &s[c.len_utf8()..];
    let base = match c {
        'B' => "byte".to_string(),
        'C' => "char".to_string(),
        'D' => "double".to_string(),
        'F' => "float".to_string(),
        'I' => "int".to_string(),
        'J' => "long".to_string(),
        'S' => "short".to_string(),
        'Z' => "boolean".to_string(),
        'V' => "void".to_string(),
        'L' => {
            let end = s.find(';')?;
            let name = s[..end].replace('/', ".");
            *s = &s[end + 1..];
            name
        }
        _ => return None,
    };
    Some(format!("{base}{}", "[]".repeat(dims)))
}

/// Java source form of a field descriptor (`[Ljava/lang/String;` →
/// `java.lang.String[]`). Unparseable input is returned unchanged.
pub fn field_type(desc: &str) -> String {
    let mut s = desc;
    match parse_type(&mut s) {
        Some(t) if s.is_empty() => t,
        _ => desc.to_string(),
    }
}

/// `(params, return)` of a method descriptor in Java source form.
pub fn method_types(desc: &str) -> Option<(Vec<String>, String)> {
    let mut s = desc.strip_prefix('(')?;
    let mut params = Vec::new();
    while !s.starts_with(')') {
        params.push(parse_type(&mut s)?);
    }
    s = &s[1..];
    let ret = parse_type(&mut s)?;
    s.is_empty().then_some((params, ret))
}

/// `void name(java.lang.String, int)`; falls back to `name desc`.
pub fn method_signature(name: &str, desc: &str) -> String {
    match method_types(desc) {
        Some((params, ret)) => format!("{ret} {name}({})", params.join(", ")),
        None => format!("{name} {desc}"),
    }
}

/// Strip the package from a dotted / internal class name.
pub fn simple_name(class: &str) -> &str {
    class.rsplit(['/', '.']).next().unwrap_or(class)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretty_prints_descriptors() {
        assert_eq!(field_type("I"), "int");
        assert_eq!(field_type("[[Ljava/lang/String;"), "java.lang.String[][]");
        assert_eq!(method_signature("run", "(Ljava/io/File;[BJ)Z"), "boolean run(java.io.File, byte[], long)");
        assert_eq!(method_signature("<init>", "()V"), "void <init>()");
        assert_eq!(method_signature("bad", "(Q)V"), "bad (Q)V");
        assert_eq!(simple_name("a/b/C$D"), "C$D");
    }
}
