// SLEIGH display/print piece formatting for instruction mnemonics.

#[derive(Debug, Clone)]
pub enum PrintPiece {
    Literal(String),
    OperandRef(u32),
    Whitespace,
    Comma,
}

#[derive(Debug, Clone)]
pub struct DisplayFormat {
    pub pieces: Vec<PrintPiece>,
}

impl DisplayFormat {
    pub fn new() -> Self { Self { pieces: Vec::new() } }

    pub fn add_literal(&mut self, text: impl Into<String>) {
        self.pieces.push(PrintPiece::Literal(text.into()));
    }
    pub fn add_operand(&mut self, index: u32) {
        self.pieces.push(PrintPiece::OperandRef(index));
    }
    pub fn add_space(&mut self) {
        self.pieces.push(PrintPiece::Whitespace);
    }
    pub fn add_comma(&mut self) {
        self.pieces.push(PrintPiece::Comma);
    }

    pub fn format(&self, operands: &[String]) -> String {
        let mut result = String::new();
        for piece in &self.pieces {
            match piece {
                PrintPiece::Literal(s) => result.push_str(s),
                PrintPiece::OperandRef(i) => {
                    if let Some(op) = operands.get(*i as usize) {
                        result.push_str(op);
                    } else {
                        result.push_str("???");
                    }
                }
                PrintPiece::Whitespace => result.push(' '),
                PrintPiece::Comma => result.push_str(", "),
            }
        }
        result
    }
}

impl Default for DisplayFormat {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_instruction() {
        let mut fmt = DisplayFormat::new();
        fmt.add_literal("MOV");
        fmt.add_space();
        fmt.add_operand(0);
        fmt.add_comma();
        fmt.add_operand(1);

        let result = fmt.format(&["RAX".into(), "RBX".into()]);
        assert_eq!(result, "MOV RAX, RBX");
    }

    #[test]
    fn format_no_operands() {
        let mut fmt = DisplayFormat::new();
        fmt.add_literal("NOP");
        assert_eq!(fmt.format(&[]), "NOP");
    }

    #[test]
    fn format_missing_operand() {
        let mut fmt = DisplayFormat::new();
        fmt.add_literal("PUSH");
        fmt.add_space();
        fmt.add_operand(5);
        assert_eq!(fmt.format(&["RAX".into()]), "PUSH ???");
    }
}
