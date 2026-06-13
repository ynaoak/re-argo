/// ClangToken AST - Ghidra's decompiler output token hierarchy.
/// Each token represents a piece of the decompiled source with
/// semantic information for highlighting and navigation.

#[derive(Debug, Clone)]
pub enum TokenType {
    FuncName,
    Type,
    VarName,
    ParamName,
    FieldName,
    Keyword,
    Operator,
    Separator,
    Number,
    StringLiteral,
    Comment,
    Label,
    Register,
    Whitespace,
    Newline,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub text: String,
    pub token_type: TokenType,
    pub address: Option<u64>,
    pub varnode_offset: Option<u64>,
}

impl Token {
    pub fn new(text: impl Into<String>, token_type: TokenType) -> Self {
        Self {
            text: text.into(),
            token_type,
            address: None,
            varnode_offset: None,
        }
    }

    pub fn with_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    pub fn keyword(text: &str) -> Self {
        Self::new(text, TokenType::Keyword)
    }
    pub fn type_name(text: &str) -> Self {
        Self::new(text, TokenType::Type)
    }
    pub fn var_name(text: &str) -> Self {
        Self::new(text, TokenType::VarName)
    }
    pub fn func_name(text: &str) -> Self {
        Self::new(text, TokenType::FuncName)
    }
    pub fn op(text: &str) -> Self {
        Self::new(text, TokenType::Operator)
    }
    pub fn sep(text: &str) -> Self {
        Self::new(text, TokenType::Separator)
    }
    pub fn num(text: &str) -> Self {
        Self::new(text, TokenType::Number)
    }
    pub fn string_lit(text: &str) -> Self {
        Self::new(text, TokenType::StringLiteral)
    }
    pub fn comment(text: &str) -> Self {
        Self::new(text, TokenType::Comment)
    }
    pub fn ws(text: &str) -> Self {
        Self::new(text, TokenType::Whitespace)
    }
    pub fn nl() -> Self {
        Self::new("\n", TokenType::Newline)
    }
}

#[derive(Debug, Clone)]
pub struct TokenLine {
    pub tokens: Vec<Token>,
    pub indent: u32,
    pub address: Option<u64>,
}

impl TokenLine {
    pub fn new(indent: u32) -> Self {
        Self {
            tokens: Vec::new(),
            indent,
            address: None,
        }
    }

    pub fn push(&mut self, token: Token) {
        self.tokens.push(token);
    }

    pub fn to_plain_text(&self) -> String {
        let indent_str = "    ".repeat(self.indent as usize);
        let content: String = self.tokens.iter().map(|t| t.text.as_str()).collect();
        format!("{}{}", indent_str, content)
    }
}

#[derive(Debug, Clone, Default)]
pub struct TokenDocument {
    pub lines: Vec<TokenLine>,
}

impl TokenDocument {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_line(&mut self, line: TokenLine) {
        self.lines.push(line);
    }

    pub fn to_plain_text(&self) -> String {
        self.lines
            .iter()
            .map(|l| l.to_plain_text())
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn line_count(&self) -> usize {
        self.lines.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_line_plain_text() {
        let mut line = TokenLine::new(1);
        line.push(Token::keyword("if"));
        line.push(Token::ws(" "));
        line.push(Token::sep("("));
        line.push(Token::var_name("x"));
        line.push(Token::ws(" "));
        line.push(Token::op("=="));
        line.push(Token::ws(" "));
        line.push(Token::num("0"));
        line.push(Token::sep(")"));
        assert_eq!(line.to_plain_text(), "    if (x == 0)");
    }

    #[test]
    fn token_document() {
        let mut doc = TokenDocument::new();
        let mut l1 = TokenLine::new(0);
        l1.push(Token::type_name("void"));
        l1.push(Token::ws(" "));
        l1.push(Token::func_name("main"));
        l1.push(Token::sep("()"));
        doc.add_line(l1);
        let mut l2 = TokenLine::new(0);
        l2.push(Token::sep("{"));
        doc.add_line(l2);
        assert_eq!(doc.line_count(), 2);
        assert!(doc.to_plain_text().contains("void main()"));
    }
}
