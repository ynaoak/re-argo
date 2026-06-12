//! YARA-lite: a small subset of YARA's rule language suitable for
//! malware-family classification using community rules.
//!
//! ## What's supported
//!
//! ```text
//! rule example_family {
//!     meta:
//!         author = "x"          // parsed but ignored
//!     strings:
//!         $a = "evil_command"
//!         $b = "Magic" nocase
//!         $c = { 4D 5A ?? ?? 50 45 }
//!     condition:
//!         $a or ($b and $c)
//!         // any of them
//!         // all of them
//!         // 2 of them
//! }
//! ```
//!
//! ## What's not supported (yet)
//!
//! * Regular-expression strings (`$x = /regex/`).
//! * `wide` / `ascii` / `fullword` modifiers.
//! * `for any i in (...)` loops.
//! * External / global rules.
//! * `imports()` / `sections()` / `filesize` helpers.
//! * Metadata semantics — the block is parsed and discarded.
//!
//! Unsupported syntax produces a clear `ParseError` instead of a
//! silent skip — callers can fall back to the full YARA binary or
//! report the rule as untranslatable.
//!
//! ## Performance
//!
//! Matching is a per-string linear scan of every executable + data
//! block. For N rules with M strings total against a B-byte binary,
//! complexity is O(M * B) plus O(M) per-condition. Plenty fast for
//! the typical case of 1-50 rules against a few MB; not a YARA
//! replacement for thousand-rule rulesets.

use std::collections::BTreeMap;

use gr_loader::BinaryInfo;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub name: String,
    pub strings: Vec<NamedString>,
    pub condition: Expr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedString {
    pub name: String,
    pub pattern: Pattern,
    pub nocase: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    /// Literal text — exact byte sequence (case sensitive unless the
    /// `NamedString.nocase` flag is set).
    Text(Vec<u8>),
    /// Hex pattern — each entry is `Some(byte)` for an exact match
    /// or `None` for a `??` wildcard. The list is byte-aligned;
    /// half-byte wildcards (`?A`) are normalised into pairs of
    /// nibble-checks during parsing.
    Hex(Vec<HexByte>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexByte {
    /// Exact byte.
    Exact(u8),
    /// Full-byte wildcard `??`.
    Wild,
    /// High-nibble fixed, low wild: `4?`.
    HighFixed(u8),
    /// Low-nibble fixed, high wild: `?A`.
    LowFixed(u8),
}

impl HexByte {
    pub fn matches(self, b: u8) -> bool {
        match self {
            Self::Exact(e) => e == b,
            Self::Wild => true,
            Self::HighFixed(h) => (b >> 4) == h,
            Self::LowFixed(l) => (b & 0xF) == l,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Ref(String),
    Not(Box<Expr>),
    And(Vec<Expr>),
    Or(Vec<Expr>),
    /// `any of them` / `all of them` / `N of them`. The `n` field is
    /// 0 → all, usize::MAX → any, otherwise the explicit minimum
    /// count.
    OfThem(OfQuantifier),
    Literal(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfQuantifier {
    Any,
    All,
    AtLeast(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    UnexpectedToken(String),
    UnexpectedEof,
    BadHexByte(String),
    UnknownModifier(String),
    UnsupportedSyntax(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedToken(t) => write!(f, "unexpected token: {}", t),
            Self::UnexpectedEof => write!(f, "unexpected EOF"),
            Self::BadHexByte(s) => write!(f, "bad hex byte: {}", s),
            Self::UnknownModifier(s) => write!(f, "unknown string modifier: {}", s),
            Self::UnsupportedSyntax(s) => write!(f, "unsupported YARA syntax: {}", s),
        }
    }
}

impl std::error::Error for ParseError {}

// ============================================================
// Tokeniser
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
    StringRef(String),
    QuotedString(String),
    /// Raw hex-pattern body — everything between `{` and matching
    /// `}` after a `=`, captured opaque. The body is re-parsed by
    /// `parse_hex_pattern` in the rule parser.
    HexBlock(Vec<u8>),
    Number(usize),
    LBrace,
    RBrace,
    LParen,
    RParen,
    Colon,
    Eq,
    Comma,
}

struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Self { src: src.as_bytes(), pos: 0 }
    }

    fn tokenise(mut self) -> Result<Vec<Token>, ParseError> {
        let mut out = Vec::new();
        while self.pos < self.src.len() {
            let c = self.src[self.pos];
            match c {
                b' ' | b'\t' | b'\r' | b'\n' => self.pos += 1,
                b'/' if self.peek_at(1) == Some(b'/') => self.skip_line_comment(),
                b'/' if self.peek_at(1) == Some(b'*') => self.skip_block_comment(),
                b'{' => {
                    // A `{` that immediately follows a `=` (modulo
                    // whitespace / comments) opens a hex-pattern
                    // block whose contents include nibble wildcards
                    // (`?`, `??`) that the normal tokeniser can't
                    // accept. Read raw bytes up to the matching `}`
                    // and emit a single HexBlock token.
                    if matches!(out.last(), Some(Token::Eq)) {
                        out.push(self.read_hex_block()?);
                    } else {
                        self.pos += 1;
                        out.push(Token::LBrace);
                    }
                }
                b'}' => {
                    self.pos += 1;
                    out.push(Token::RBrace);
                }
                b'(' => {
                    self.pos += 1;
                    out.push(Token::LParen);
                }
                b')' => {
                    self.pos += 1;
                    out.push(Token::RParen);
                }
                b':' => {
                    self.pos += 1;
                    out.push(Token::Colon);
                }
                b'=' => {
                    self.pos += 1;
                    out.push(Token::Eq);
                }
                b',' => {
                    self.pos += 1;
                    out.push(Token::Comma);
                }
                b'$' => out.push(self.read_string_ref()?),
                b'"' => out.push(self.read_quoted()?),
                b'0'..=b'9' => out.push(self.read_number()),
                b'a'..=b'z' | b'A'..=b'Z' | b'_' => out.push(self.read_ident_or_hex_block()?),
                _ => return Err(ParseError::UnexpectedToken(format!("char {:?}", c as char))),
            }
        }
        Ok(out)
    }

    fn read_hex_block(&mut self) -> Result<Token, ParseError> {
        self.pos += 1; // skip opening {
        let start = self.pos;
        let mut depth = 1;
        while self.pos < self.src.len() && depth > 0 {
            match self.src[self.pos] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            self.pos += 1;
        }
        if depth != 0 {
            return Err(ParseError::UnexpectedEof);
        }
        let body = self.src[start..self.pos].to_vec();
        self.pos += 1; // skip closing }
        Ok(Token::HexBlock(body))
    }

    fn peek_at(&self, off: usize) -> Option<u8> {
        self.src.get(self.pos + off).copied()
    }

    fn skip_line_comment(&mut self) {
        while self.pos < self.src.len() && self.src[self.pos] != b'\n' {
            self.pos += 1;
        }
    }

    fn skip_block_comment(&mut self) {
        self.pos += 2;
        while self.pos + 1 < self.src.len() {
            if self.src[self.pos] == b'*' && self.src[self.pos + 1] == b'/' {
                self.pos += 2;
                return;
            }
            self.pos += 1;
        }
        self.pos = self.src.len();
    }

    fn read_string_ref(&mut self) -> Result<Token, ParseError> {
        self.pos += 1; // skip $
        let start = self.pos;
        while self.pos < self.src.len() && is_ident_byte(self.src[self.pos]) {
            self.pos += 1;
        }
        let s = std::str::from_utf8(&self.src[start..self.pos])
            .map_err(|_| ParseError::UnexpectedToken("non-utf8 ident".into()))?;
        Ok(Token::StringRef(s.to_string()))
    }

    fn read_quoted(&mut self) -> Result<Token, ParseError> {
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.src.len() {
            let c = self.src[self.pos];
            if c == b'"' {
                self.pos += 1;
                return Ok(Token::QuotedString(out));
            }
            if c == b'\\' && self.pos + 1 < self.src.len() {
                self.pos += 1;
                let esc = self.src[self.pos];
                self.pos += 1;
                match esc {
                    b'n' => out.push('\n'),
                    b't' => out.push('\t'),
                    b'r' => out.push('\r'),
                    b'\\' => out.push('\\'),
                    b'"' => out.push('"'),
                    b'0' => out.push('\0'),
                    b'x' => {
                        if self.pos + 1 >= self.src.len() {
                            return Err(ParseError::UnexpectedEof);
                        }
                        let h = (hex_val(self.src[self.pos])? << 4)
                            | hex_val(self.src[self.pos + 1])?;
                        out.push(h as char);
                        self.pos += 2;
                    }
                    other => return Err(ParseError::UnexpectedToken(format!("\\{}", other as char))),
                }
                continue;
            }
            out.push(c as char);
            self.pos += 1;
        }
        Err(ParseError::UnexpectedEof)
    }

    fn read_number(&mut self) -> Token {
        let start = self.pos;
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        let n: usize = std::str::from_utf8(&self.src[start..self.pos])
            .unwrap()
            .parse()
            .unwrap_or(0);
        Token::Number(n)
    }

    fn read_ident_or_hex_block(&mut self) -> Result<Token, ParseError> {
        let start = self.pos;
        while self.pos < self.src.len() && is_ident_byte(self.src[self.pos]) {
            self.pos += 1;
        }
        let s = std::str::from_utf8(&self.src[start..self.pos])
            .map_err(|_| ParseError::UnexpectedToken("non-utf8 ident".into()))?;
        Ok(Token::Ident(s.to_string()))
    }

}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn hex_val(b: u8) -> Result<u8, ParseError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(ParseError::BadHexByte(format!("{:?}", b as char))),
    }
}

// ============================================================
// Parser
// ============================================================

/// Parse one or more `rule` definitions from a `.yar` source string.
pub fn parse_rules(src: &str) -> Result<Vec<Rule>, ParseError> {
    let tokens = Lexer::new(src).tokenise()?;
    let mut p = Parser { tokens, cursor: 0 };
    let mut rules = Vec::new();
    while !p.at_eof() {
        rules.push(p.parse_rule()?);
    }
    Ok(rules)
}

struct Parser {
    tokens: Vec<Token>,
    cursor: usize,
}

impl Parser {
    fn at_eof(&self) -> bool {
        self.cursor >= self.tokens.len()
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.cursor)
    }

    fn bump(&mut self) -> Result<Token, ParseError> {
        let t = self.tokens.get(self.cursor).cloned().ok_or(ParseError::UnexpectedEof)?;
        self.cursor += 1;
        Ok(t)
    }

    fn expect_ident(&mut self, want: &str) -> Result<(), ParseError> {
        match self.bump()? {
            Token::Ident(s) if s == want => Ok(()),
            other => Err(ParseError::UnexpectedToken(format!(
                "expected `{}`, got {:?}",
                want, other
            ))),
        }
    }

    fn expect(&mut self, t: Token) -> Result<(), ParseError> {
        let got = self.bump()?;
        if got == t {
            Ok(())
        } else {
            Err(ParseError::UnexpectedToken(format!(
                "expected {:?}, got {:?}",
                t, got
            )))
        }
    }

    fn parse_rule(&mut self) -> Result<Rule, ParseError> {
        // `private` / `global` qualifiers in front of `rule`.
        match self.peek() {
            Some(Token::Ident(s)) if s == "private" || s == "global" => {
                self.bump()?;
            }
            _ => {}
        }
        self.expect_ident("rule")?;
        let name = match self.bump()? {
            Token::Ident(n) => n,
            other => return Err(ParseError::UnexpectedToken(format!("rule name: {:?}", other))),
        };
        // Skip optional rule tags (`rule X : tag1 tag2 { ... }`).
        if matches!(self.peek(), Some(Token::Colon)) {
            self.bump()?;
            while let Some(Token::Ident(_)) = self.peek() {
                self.bump()?;
            }
        }
        self.expect(Token::LBrace)?;

        let mut strings: Vec<NamedString> = Vec::new();
        let mut condition: Option<Expr> = None;

        loop {
            match self.peek() {
                Some(Token::RBrace) => {
                    self.bump()?;
                    break;
                }
                Some(Token::Ident(s)) if s == "meta" => {
                    self.bump()?;
                    self.expect(Token::Colon)?;
                    self.skip_meta()?;
                }
                Some(Token::Ident(s)) if s == "strings" => {
                    self.bump()?;
                    self.expect(Token::Colon)?;
                    strings = self.parse_strings()?;
                }
                Some(Token::Ident(s)) if s == "condition" => {
                    self.bump()?;
                    self.expect(Token::Colon)?;
                    condition = Some(self.parse_or()?);
                }
                Some(other) => {
                    return Err(ParseError::UnexpectedToken(format!("rule body: {:?}", other)));
                }
                None => return Err(ParseError::UnexpectedEof),
            }
        }

        Ok(Rule {
            name,
            strings,
            condition: condition.ok_or_else(|| {
                ParseError::UnexpectedToken("missing `condition:` section".into())
            })?,
        })
    }

    fn skip_meta(&mut self) -> Result<(), ParseError> {
        // Eat tokens until the next section start.
        while let Some(t) = self.peek() {
            match t {
                Token::Ident(s) if s == "strings" || s == "condition" => return Ok(()),
                Token::RBrace => return Ok(()),
                _ => {
                    self.bump()?;
                }
            }
        }
        Ok(())
    }

    fn parse_strings(&mut self) -> Result<Vec<NamedString>, ParseError> {
        let mut out = Vec::new();
        while let Some(t) = self.peek() {
            match t {
                Token::Ident(s) if s == "condition" => break,
                Token::RBrace => break,
                Token::StringRef(_) => {
                    let name = match self.bump()? {
                        Token::StringRef(n) => n,
                        _ => unreachable!(),
                    };
                    self.expect(Token::Eq)?;
                    let (pattern, nocase) = self.parse_string_value()?;
                    out.push(NamedString { name, pattern, nocase });
                }
                other => {
                    return Err(ParseError::UnexpectedToken(format!(
                        "strings section: {:?}",
                        other
                    )))
                }
            }
        }
        Ok(out)
    }

    fn parse_string_value(&mut self) -> Result<(Pattern, bool), ParseError> {
        let pattern = match self.bump()? {
            Token::QuotedString(s) => Pattern::Text(s.into_bytes()),
            Token::HexBlock(body) => Pattern::Hex(parse_hex_pattern(&body)?),
            other => return Err(ParseError::UnexpectedToken(format!("string value: {:?}", other))),
        };
        let mut nocase = false;
        while let Some(Token::Ident(s)) = self.peek().cloned() {
            // Modifiers: nocase / wide / ascii / fullword. Anything
            // unsupported errors out (so analysts know).
            match s.as_str() {
                "nocase" => {
                    self.bump()?;
                    nocase = true;
                }
                "ascii" => {
                    // Default for text strings — no-op for our scope.
                    self.bump()?;
                }
                "wide" | "fullword" => {
                    return Err(ParseError::UnknownModifier(s));
                }
                "condition" | "strings" => break,
                _ => break,
            }
        }
        Ok((pattern, nocase))
    }

    // condition := disjunction
    fn parse_or(&mut self) -> Result<Expr, ParseError> {
        let mut parts = vec![self.parse_and()?];
        while let Some(Token::Ident(s)) = self.peek()
            && s == "or"
        {
            self.bump()?;
            parts.push(self.parse_and()?);
        }
        Ok(if parts.len() == 1 {
            parts.into_iter().next().unwrap()
        } else {
            Expr::Or(parts)
        })
    }

    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut parts = vec![self.parse_not()?];
        while let Some(Token::Ident(s)) = self.peek()
            && s == "and"
        {
            self.bump()?;
            parts.push(self.parse_not()?);
        }
        Ok(if parts.len() == 1 {
            parts.into_iter().next().unwrap()
        } else {
            Expr::And(parts)
        })
    }

    fn parse_not(&mut self) -> Result<Expr, ParseError> {
        if let Some(Token::Ident(s)) = self.peek()
            && s == "not"
        {
            self.bump()?;
            return Ok(Expr::Not(Box::new(self.parse_not()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        match self.peek() {
            Some(Token::LParen) => {
                self.bump()?;
                let e = self.parse_or()?;
                self.expect(Token::RParen)?;
                Ok(e)
            }
            Some(Token::StringRef(_)) => {
                let n = match self.bump()? {
                    Token::StringRef(n) => n,
                    _ => unreachable!(),
                };
                Ok(Expr::Ref(n))
            }
            Some(Token::Ident(s)) if s == "true" => {
                self.bump()?;
                Ok(Expr::Literal(true))
            }
            Some(Token::Ident(s)) if s == "false" => {
                self.bump()?;
                Ok(Expr::Literal(false))
            }
            // `any of them`, `all of them`, `N of them`
            Some(Token::Ident(s)) if s == "any" || s == "all" => {
                let s = match self.bump()? {
                    Token::Ident(s) => s,
                    _ => unreachable!(),
                };
                self.expect_ident("of")?;
                self.expect_ident("them")?;
                Ok(Expr::OfThem(if s == "any" {
                    OfQuantifier::Any
                } else {
                    OfQuantifier::All
                }))
            }
            Some(Token::Number(_)) => {
                let n = match self.bump()? {
                    Token::Number(n) => n,
                    _ => unreachable!(),
                };
                self.expect_ident("of")?;
                self.expect_ident("them")?;
                Ok(Expr::OfThem(OfQuantifier::AtLeast(n)))
            }
            Some(other) => Err(ParseError::UnexpectedToken(format!(
                "condition primary: {:?}",
                other
            ))),
            None => Err(ParseError::UnexpectedEof),
        }
    }
}

fn parse_hex_pattern(body: &[u8]) -> Result<Vec<HexByte>, ParseError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < body.len() {
        let c = body[i];
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'/' if body.get(i + 1).copied() == Some(b'/') => {
                while i < body.len() && body[i] != b'\n' {
                    i += 1;
                }
            }
            _ => {
                if i + 1 >= body.len() {
                    return Err(ParseError::BadHexByte("trailing nibble".into()));
                }
                let hi = body[i];
                let lo = body[i + 1];
                let hb = match (hi, lo) {
                    (b'?', b'?') => HexByte::Wild,
                    (b'?', l) => HexByte::LowFixed(hex_val(l)?),
                    (h, b'?') => HexByte::HighFixed(hex_val(h)?),
                    (h, l) => HexByte::Exact((hex_val(h)? << 4) | hex_val(l)?),
                };
                out.push(hb);
                i += 2;
            }
        }
    }
    if out.is_empty() {
        return Err(ParseError::BadHexByte("empty hex pattern".into()));
    }
    Ok(out)
}

// ============================================================
// Matching
// ============================================================

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule: String,
    /// Per-string matches: name → list of virtual addresses.
    pub string_hits: BTreeMap<String, Vec<u64>>,
}

/// Scan a binary for occurrences of every rule's string patterns,
/// then evaluate each rule's condition. Returns one entry per
/// MATCHED rule (rules whose condition evaluated to true).
pub fn scan(info: &BinaryInfo, rules: &[Rule]) -> Vec<RuleMatch> {
    let mut out = Vec::new();
    for rule in rules {
        let mut hits: BTreeMap<String, Vec<u64>> = BTreeMap::new();
        for s in &rule.strings {
            hits.insert(s.name.clone(), Vec::new());
        }
        for block in info.memory.blocks() {
            let Some(data) = &block.data else {
                continue;
            };
            for s in &rule.strings {
                let positions = match &s.pattern {
                    Pattern::Text(needle) => find_text(data, needle, s.nocase),
                    Pattern::Hex(pat) => find_hex(data, pat),
                };
                if let Some(slot) = hits.get_mut(&s.name) {
                    for p in positions {
                        slot.push(block.start + p as u64);
                    }
                }
            }
        }
        if eval(&rule.condition, &hits) {
            out.push(RuleMatch {
                rule: rule.name.clone(),
                string_hits: hits,
            });
        }
    }
    out
}

fn eval(e: &Expr, hits: &BTreeMap<String, Vec<u64>>) -> bool {
    match e {
        Expr::Literal(b) => *b,
        Expr::Ref(name) => hits.get(name).is_some_and(|v| !v.is_empty()),
        Expr::Not(inner) => !eval(inner, hits),
        Expr::And(parts) => parts.iter().all(|p| eval(p, hits)),
        Expr::Or(parts) => parts.iter().any(|p| eval(p, hits)),
        Expr::OfThem(q) => {
            let total = hits.len();
            let matched = hits.values().filter(|v| !v.is_empty()).count();
            match q {
                OfQuantifier::Any => matched > 0,
                OfQuantifier::All => total > 0 && matched == total,
                OfQuantifier::AtLeast(n) => matched >= *n,
            }
        }
    }
}

fn find_text(haystack: &[u8], needle: &[u8], nocase: bool) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    if nocase {
        let needle_l: Vec<u8> = needle.iter().map(|b| b.to_ascii_lowercase()).collect();
        for i in 0..=haystack.len() - needle.len() {
            if haystack[i..i + needle.len()]
                .iter()
                .zip(needle_l.iter())
                .all(|(a, b)| a.to_ascii_lowercase() == *b)
            {
                out.push(i);
            }
        }
    } else {
        for i in 0..=haystack.len() - needle.len() {
            if haystack[i..i + needle.len()] == *needle {
                out.push(i);
            }
        }
    }
    out
}

fn find_hex(haystack: &[u8], pat: &[HexByte]) -> Vec<usize> {
    if pat.is_empty() || haystack.len() < pat.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0..=haystack.len() - pat.len() {
        if pat
            .iter()
            .enumerate()
            .all(|(j, h)| h.matches(haystack[i + j]))
        {
            out.push(i);
        }
    }
    out
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_rule() {
        let src = r#"
            rule sample {
                strings:
                    $a = "hello"
                condition:
                    $a
            }
        "#;
        let rules = parse_rules(src).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "sample");
        assert_eq!(rules[0].strings.len(), 1);
        assert!(matches!(rules[0].condition, Expr::Ref(ref n) if n == "a"));
    }

    #[test]
    fn parse_hex_with_wildcards() {
        let src = r#"
            rule h {
                strings:
                    $h = { 4D 5A ?? ?? 50 45 }
                condition:
                    $h
            }
        "#;
        let rules = parse_rules(src).unwrap();
        let Pattern::Hex(pat) = &rules[0].strings[0].pattern else {
            panic!("expected hex");
        };
        assert_eq!(pat.len(), 6);
        assert_eq!(pat[0], HexByte::Exact(0x4D));
        assert_eq!(pat[1], HexByte::Exact(0x5A));
        assert_eq!(pat[2], HexByte::Wild);
        assert_eq!(pat[3], HexByte::Wild);
    }

    #[test]
    fn parse_half_byte_wildcards() {
        let src = r#"
            rule h {
                strings:
                    $h = { 4? ?A }
                condition:
                    $h
            }
        "#;
        let rules = parse_rules(src).unwrap();
        let Pattern::Hex(pat) = &rules[0].strings[0].pattern else { panic!() };
        assert_eq!(pat[0], HexByte::HighFixed(4));
        assert_eq!(pat[1], HexByte::LowFixed(0xA));
    }

    #[test]
    fn parse_and_or_not() {
        let src = r#"
            rule c {
                strings:
                    $a = "x" $b = "y" $c = "z"
                condition:
                    $a and ($b or not $c)
            }
        "#;
        let rules = parse_rules(src).unwrap();
        let Expr::And(parts) = &rules[0].condition else {
            panic!("expected And, got {:?}", rules[0].condition);
        };
        assert_eq!(parts.len(), 2);
    }

    #[test]
    fn parse_any_of_them() {
        let src = r#"
            rule q {
                strings:
                    $a = "x" $b = "y"
                condition:
                    any of them
            }
        "#;
        let rules = parse_rules(src).unwrap();
        assert!(matches!(rules[0].condition, Expr::OfThem(OfQuantifier::Any)));
    }

    #[test]
    fn parse_n_of_them() {
        let src = r#"
            rule q {
                strings:
                    $a = "x" $b = "y" $c = "z"
                condition:
                    2 of them
            }
        "#;
        let rules = parse_rules(src).unwrap();
        assert!(matches!(
            rules[0].condition,
            Expr::OfThem(OfQuantifier::AtLeast(2))
        ));
    }

    #[test]
    fn parse_meta_block_ignored() {
        let src = r#"
            rule m {
                meta:
                    author = "test"
                    date = "2020"
                strings:
                    $a = "x"
                condition:
                    $a
            }
        "#;
        let rules = parse_rules(src).unwrap();
        assert_eq!(rules[0].strings.len(), 1);
    }

    #[test]
    fn parse_nocase_modifier() {
        let src = r#"
            rule n {
                strings:
                    $a = "Magic" nocase
                condition:
                    $a
            }
        "#;
        let rules = parse_rules(src).unwrap();
        assert!(rules[0].strings[0].nocase);
    }

    #[test]
    fn parse_rejects_wide_modifier() {
        let src = r#"
            rule w {
                strings:
                    $a = "abc" wide
                condition:
                    $a
            }
        "#;
        let err = parse_rules(src).unwrap_err();
        assert!(matches!(err, ParseError::UnknownModifier(_)));
    }

    #[test]
    fn comments_skipped() {
        let src = r#"
            // line comment
            /* block
               comment */
            rule c {
                strings:
                    $a = "x" // tail
                condition:
                    $a
            }
        "#;
        let rules = parse_rules(src).unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn find_text_basic() {
        let pos = find_text(b"hello world hello", b"hello", false);
        assert_eq!(pos, vec![0, 12]);
    }

    #[test]
    fn find_text_nocase() {
        let pos = find_text(b"Hello HELLO hello", b"hello", true);
        assert_eq!(pos, vec![0, 6, 12]);
    }

    #[test]
    fn find_hex_with_wildcards() {
        let pat = vec![HexByte::Exact(0x4D), HexByte::Exact(0x5A), HexByte::Wild];
        let pos = find_hex(&[0x4D, 0x5A, 0x00, 0x4D, 0x5A, 0xFF], &pat);
        assert_eq!(pos, vec![0, 3]);
    }

    #[test]
    fn find_hex_half_byte() {
        // High nibble 4, low wild.
        let pat = vec![HexByte::HighFixed(4)];
        let pos = find_hex(&[0x40, 0x41, 0x50, 0x4F], &pat);
        assert_eq!(pos, vec![0, 1, 3]);
    }

    #[test]
    fn eval_and_or_not() {
        let mut hits: BTreeMap<String, Vec<u64>> = BTreeMap::new();
        hits.insert("a".into(), vec![0]);
        hits.insert("b".into(), vec![]);
        assert!(eval(&Expr::Ref("a".into()), &hits));
        assert!(!eval(&Expr::Ref("b".into()), &hits));
        assert!(eval(
            &Expr::Or(vec![Expr::Ref("a".into()), Expr::Ref("b".into())]),
            &hits
        ));
        assert!(!eval(
            &Expr::And(vec![Expr::Ref("a".into()), Expr::Ref("b".into())]),
            &hits
        ));
        assert!(eval(&Expr::Not(Box::new(Expr::Ref("b".into()))), &hits));
    }

    #[test]
    fn eval_of_them_quantifiers() {
        let mut hits: BTreeMap<String, Vec<u64>> = BTreeMap::new();
        hits.insert("a".into(), vec![0]);
        hits.insert("b".into(), vec![]);
        hits.insert("c".into(), vec![1]);
        assert!(eval(&Expr::OfThem(OfQuantifier::Any), &hits));
        assert!(!eval(&Expr::OfThem(OfQuantifier::All), &hits));
        assert!(eval(&Expr::OfThem(OfQuantifier::AtLeast(2)), &hits));
        assert!(!eval(&Expr::OfThem(OfQuantifier::AtLeast(3)), &hits));
    }
}
