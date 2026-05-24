// PrintC / PrintRust: final code output formatters.

use crate::token::{Token, TokenLine, TokenType};

pub struct PrintC {
    pub indent_width: u32,
    pub brace_style: BraceStyle,
    pub max_line_width: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum BraceStyle {
    Allman,
    KAndR,
}

impl PrintC {
    pub fn new() -> Self {
        Self { indent_width: 4, brace_style: BraceStyle::KAndR, max_line_width: 100 }
    }

    pub fn format_function_header(&self, return_type: &str, name: &str, params: &[(String, String)]) -> TokenLine {
        let mut line = TokenLine::new(0);
        line.push(Token::type_name(return_type));
        line.push(Token::ws(" "));
        line.push(Token::func_name(name));
        line.push(Token::sep("("));
        for (i, (ptype, pname)) in params.iter().enumerate() {
            if i > 0 { line.push(Token::sep(", ")); }
            line.push(Token::type_name(ptype));
            line.push(Token::ws(" "));
            line.push(Token::var_name(pname));
        }
        if params.is_empty() { line.push(Token::keyword("void")); }
        line.push(Token::sep(")"));
        line
    }

    pub fn format_return(&self, expr: &str) -> TokenLine {
        let mut line = TokenLine::new(1);
        line.push(Token::keyword("return"));
        line.push(Token::ws(" "));
        line.push(Token::new(expr, TokenType::Number));
        line.push(Token::sep(";"));
        line
    }

    pub fn format_assignment(&self, var: &str, expr: &str, indent: u32) -> TokenLine {
        let mut line = TokenLine::new(indent);
        line.push(Token::var_name(var));
        line.push(Token::ws(" "));
        line.push(Token::op("="));
        line.push(Token::ws(" "));
        line.push(Token::new(expr, TokenType::Number));
        line.push(Token::sep(";"));
        line
    }

    pub fn format_call(&self, func: &str, args: &[&str], indent: u32) -> TokenLine {
        let mut line = TokenLine::new(indent);
        line.push(Token::func_name(func));
        line.push(Token::sep("("));
        for (i, arg) in args.iter().enumerate() {
            if i > 0 { line.push(Token::sep(", ")); }
            line.push(Token::var_name(arg));
        }
        line.push(Token::sep(")"));
        line.push(Token::sep(";"));
        line
    }
}

impl Default for PrintC {
    fn default() -> Self { Self::new() }
}

pub struct PrintRust;

impl PrintRust {
    pub fn format_function_header(name: &str, params: &[(String, String)], return_type: &str) -> TokenLine {
        let mut line = TokenLine::new(0);
        line.push(Token::keyword("fn"));
        line.push(Token::ws(" "));
        line.push(Token::func_name(name));
        line.push(Token::sep("("));
        for (i, (pname, ptype)) in params.iter().enumerate() {
            if i > 0 { line.push(Token::sep(", ")); }
            line.push(Token::var_name(pname));
            line.push(Token::sep(": "));
            line.push(Token::type_name(&rust_type(ptype)));
        }
        line.push(Token::sep(")"));
        if return_type != "void" {
            line.push(Token::ws(" "));
            line.push(Token::sep("->"));
            line.push(Token::ws(" "));
            line.push(Token::type_name(&rust_type(return_type)));
        }
        line
    }
}

fn rust_type(c_type: &str) -> String {
    match c_type {
        "void" => "()".into(),
        "int" | "int32_t" => "i32".into(),
        "unsigned int" | "uint32_t" => "u32".into(),
        "int64_t" | "long long" => "i64".into(),
        "uint64_t" | "unsigned long long" => "u64".into(),
        "int8_t" | "char" => "i8".into(),
        "uint8_t" | "unsigned char" => "u8".into(),
        "int16_t" | "short" => "i16".into(),
        "uint16_t" | "unsigned short" => "u16".into(),
        "float" => "f32".into(),
        "double" => "f64".into(),
        "bool" | "_Bool" => "bool".into(),
        "size_t" => "usize".into(),
        s if s.ends_with('*') => format!("*mut {}", rust_type(s.trim_end_matches('*').trim())),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_c_function_header() {
        let printer = PrintC::new();
        let line = printer.format_function_header("int", "main", &[
            ("int".into(), "argc".into()),
            ("char**".into(), "argv".into()),
        ]);
        let text = line.to_plain_text();
        assert!(text.contains("int main(int argc, char** argv)"));
    }

    #[test]
    fn print_c_void() {
        let printer = PrintC::new();
        let line = printer.format_function_header("void", "init", &[]);
        assert!(line.to_plain_text().contains("void init(void)"));
    }

    #[test]
    fn print_rust_header() {
        let line = PrintRust::format_function_header("add", &[
            ("a".into(), "int32_t".into()),
            ("b".into(), "int32_t".into()),
        ], "int32_t");
        let text = line.to_plain_text();
        assert!(text.contains("fn add(a: i32, b: i32) -> i32"));
    }

    #[test]
    fn rust_type_mapping() {
        assert_eq!(rust_type("int"), "i32");
        assert_eq!(rust_type("uint64_t"), "u64");
        assert_eq!(rust_type("double"), "f64");
        assert_eq!(rust_type("void"), "()");
        assert_eq!(rust_type("size_t"), "usize");
    }
}
