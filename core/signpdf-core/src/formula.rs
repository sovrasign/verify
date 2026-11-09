//! Formula fields: a small, exact formula language over other fields' values.
//!
//! A formula field computes its value from number fields, other formula fields, checkboxes
//! (ticked is 1, not ticked 0) and dropdowns whose options map to numbers: a quantity times a
//! unit price, a total, a payment amount. The signer's page shows it live, the engine computes
//! and draws it when the signer signs, and the verifier computes it again and rejects a document
//! whose drawn value differs. All three use this module and [`crate::decimal`] arithmetic, so
//! they agree to the last digit.
//!
//! ## The language
//!
//! ```text
//! {quantity} * {unit_price} + if({express} = 1, 15, 0)
//! round(sum({line1}, {line2}, {line3}) * 1.2, 2)
//! ```
//!
//! - Numbers: `12`, `0.5` (no exponent, no leading zeros, `.` as the decimal point).
//! - Field references: the field's id in braces, `{unit_price}`.
//! - Arithmetic: `+`, `-`, `*`, `/` (also `−`, `×` and `÷`), unary minus and parentheses, with
//!   the usual precedence. A quotient keeps [`MAX_SCALE`] decimal places, rounded half up.
//! - Comparisons, for conditions: `=`, `<>` (or `!=`), `<`, `<=`, `>`, `>=`.
//! - Functions (names in any case): `sum(a, …)`, `min(a, …)`, `max(a, …)`, `round(x, n)` with
//!   `n` from 0 to [`MAX_SCALE`] (half up, away from zero on a tie), `if(condition, a, b)`,
//!   `and(c, …)`, `or(c, …)` and `not(c)`.
//!
//! A formula's result is a number; conditions are only for `if`, `and`, `or` and `not`. `if`
//! evaluates only the branch it takes. Errors (a division by zero, a number out of range, an
//! unknown field) are errors, never infinity or a silent zero. Rounding the result to the
//! field's decimal places is the field's job, not the formula's.
//!
//! ## Formula fields in the envelope (schema version 8)
//!
//! A field of type `formula` seals a [`FormulaSpec`] (the formula text and the numbers that the
//! options of the dropdowns and radio groups it reads count as) and a `number_format` (decimal
//! places, drawing style, optional currency). A reference `{x}` names a field by id (a number,
//! a checkbox, a dropdown or another formula) or, when no field has that id, a radio group by
//! its group name. [`check_formula_fields`] applies the preparation rules: every reference is
//! known and holds a number, it is filled by the formula's own signer or, under a sequential
//! policy, by a signer of a lower order (who has always signed before), every option of a
//! dropdown or radio group it reads has a number in the map, and formulas do not read each other
//! in a loop. [`compute_formula_fields`] computes the values: at signing (the signer types
//! nothing in a formula field), in the verifier, which recomputes them from the values the
//! revision holds and rejects a mismatch, and in hosts (the WebAssembly
//! `signpdf_compute_formulas`) for the live display.
//!
//! Inputs count as: a number field its value, or 0 when left empty; a checkbox 1 when ticked,
//! else 0; a dropdown or radio group the number its map gives the chosen option, or 0 when none
//! is chosen; another formula field its stored value (rounded to its decimal places, as drawn).
//! The result is rounded half up to the field's decimal places.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::decimal::{Decimal, DecimalError, MAX_SCALE};
use crate::model::{Field, FieldType, SigningOrder};

/// The longest formula text, in bytes.
pub const MAX_FORMULA_LEN: usize = 2000;

/// The deepest nesting of parentheses, function calls and unary minus.
pub const MAX_DEPTH: usize = 32;

/// Why a formula could not be read or computed. [`FormulaError::code`] is stable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormulaError {
    /// The text is not a formula: `reason` at byte offset `at`.
    Syntax { at: usize, reason: &'static str },
    /// Longer than [`MAX_FORMULA_LEN`].
    TooLong,
    /// Nested deeper than [`MAX_DEPTH`].
    TooDeep,
    /// A function this language does not have.
    UnknownFunction(String),
    /// A function called with the wrong number or kind of arguments.
    Arguments(&'static str),
    /// A condition where a number is needed, or a number where a condition is needed.
    Type(&'static str),
    /// A field the formula reads has no value to give (unknown to the caller).
    UnknownField(String),
    /// Arithmetic failed: division by zero, or a value out of range.
    Arithmetic(DecimalError),
    /// Formula fields that read each other in a loop, in loop order.
    Loop(Vec<String>),
}

impl FormulaError {
    /// A stable code for the error, in `snake_case`.
    pub fn code(&self) -> &'static str {
        match self {
            FormulaError::Syntax { .. } => "formula_syntax",
            FormulaError::TooLong => "formula_too_long",
            FormulaError::TooDeep => "formula_too_deep",
            FormulaError::UnknownFunction(_) => "formula_unknown_function",
            FormulaError::Arguments(_) => "formula_arguments",
            FormulaError::Type(_) => "formula_type",
            FormulaError::UnknownField(_) => "formula_unknown_field",
            FormulaError::Arithmetic(e) => e.code(),
            FormulaError::Loop(_) => "formula_loop",
        }
    }
}

impl fmt::Display for FormulaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormulaError::Syntax { at, reason } => write!(f, "{reason} at position {at}"),
            FormulaError::TooLong => write!(f, "formula longer than {MAX_FORMULA_LEN} bytes"),
            FormulaError::TooDeep => write!(f, "formula nested deeper than {MAX_DEPTH}"),
            FormulaError::UnknownFunction(name) => write!(f, "unknown function {name}"),
            FormulaError::Arguments(name) => write!(f, "wrong arguments for {name}"),
            FormulaError::Type(what) => write!(f, "{what}"),
            FormulaError::UnknownField(id) => write!(f, "no value for field {{{id}}}"),
            FormulaError::Arithmetic(e) => write!(f, "{e}"),
            FormulaError::Loop(ids) => write!(f, "formulas read each other: {}", ids.join(" → ")),
        }
    }
}

impl std::error::Error for FormulaError {}

impl From<DecimalError> for FormulaError {
    fn from(e: DecimalError) -> Self {
        FormulaError::Arithmetic(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Func {
    Sum,
    Min,
    Max,
    Round,
    If,
    And,
    Or,
    Not,
}

impl Func {
    fn from_name(name: &str) -> Option<Func> {
        Some(match name.to_ascii_lowercase().as_str() {
            "sum" => Func::Sum,
            "min" => Func::Min,
            "max" => Func::Max,
            "round" => Func::Round,
            "if" => Func::If,
            "and" => Func::And,
            "or" => Func::Or,
            "not" => Func::Not,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Func::Sum => "sum",
            Func::Min => "min",
            Func::Max => "max",
            Func::Round => "round",
            Func::If => "if",
            Func::And => "and",
            Func::Or => "or",
            Func::Not => "not",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Expr {
    Number(Decimal),
    Field(String),
    Neg(Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
    Compare(CmpOp, Box<Expr>, Box<Expr>),
    Call(Func, Vec<Expr>),
}

/// A value while evaluating: a number, or a condition's truth.
#[derive(Debug, Clone, Copy)]
enum Value {
    Number(Decimal),
    Bool(bool),
}

impl Value {
    fn number(self) -> Result<Decimal, FormulaError> {
        match self {
            Value::Number(n) => Ok(n),
            Value::Bool(_) => Err(FormulaError::Type("a number is needed, not a condition")),
        }
    }

    fn truth(self) -> Result<bool, FormulaError> {
        match self {
            Value::Bool(b) => Ok(b),
            Value::Number(_) => Err(FormulaError::Type("a condition is needed, not a number")),
        }
    }
}

/// A parsed formula.
#[derive(Debug, Clone, PartialEq)]
pub struct Formula {
    root: Expr,
    fields: Vec<String>,
}

impl Formula {
    /// Reads a formula. A formula whose result would be a condition rather than a number is
    /// refused here, as are unknown functions and calls with the wrong number of arguments.
    pub fn parse(text: &str) -> Result<Formula, FormulaError> {
        if text.len() > MAX_FORMULA_LEN {
            return Err(FormulaError::TooLong);
        }
        let tokens = tokenize(text)?;
        let mut parser = Parser {
            tokens: &tokens,
            pos: 0,
            depth: 0,
            end: text.len(),
        };
        let root = parser.expr()?;
        if let Some((at, _)) = parser.tokens.get(parser.pos) {
            return Err(FormulaError::Syntax {
                at: *at,
                reason: "unexpected text after the formula",
            });
        }
        if kind_of(&root)? != Kind::Number {
            return Err(FormulaError::Type("a formula's result must be a number"));
        }
        let mut fields = Vec::new();
        collect_fields(&root, &mut fields);
        Ok(Formula { root, fields })
    }

    /// The ids of the fields the formula reads, each once, in the order they first appear.
    pub fn fields(&self) -> &[String] {
        &self.fields
    }

    /// Computes the formula. `value_of` gives each field's value as a number (checkbox 1 or 0, a
    /// dropdown's mapped number, an empty answer as the field's rules say), or `None` for a field
    /// it does not know, which is an error.
    pub fn evaluate(
        &self,
        value_of: impl Fn(&str) -> Option<Decimal>,
    ) -> Result<Decimal, FormulaError> {
        eval(&self.root, &value_of)?.number()
    }
}

/// The order in which to compute formula fields that read other formula fields: every formula
/// comes after the formulas it reads. `formulas` maps each formula field's id to its formula;
/// reads of other fields are ignored here. Formulas that read each other in a loop are refused
/// with the loop ([`FormulaError::Loop`]).
pub fn evaluation_order(formulas: &BTreeMap<String, Formula>) -> Result<Vec<String>, FormulaError> {
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        Visiting,
        Done,
    }
    fn visit(
        id: &str,
        formulas: &BTreeMap<String, Formula>,
        marks: &mut BTreeMap<String, Mark>,
        path: &mut Vec<String>,
        order: &mut Vec<String>,
    ) -> Result<(), FormulaError> {
        match marks.get(id) {
            Some(Mark::Done) => return Ok(()),
            Some(Mark::Visiting) => {
                let start = path.iter().position(|p| p == id).unwrap_or(0);
                let mut cycle = path[start..].to_vec();
                cycle.push(id.to_string());
                return Err(FormulaError::Loop(cycle));
            }
            None => {}
        }
        marks.insert(id.to_string(), Mark::Visiting);
        path.push(id.to_string());
        for dep in formulas[id].fields() {
            if formulas.contains_key(dep) {
                visit(dep, formulas, marks, path, order)?;
            }
        }
        path.pop();
        marks.insert(id.to_string(), Mark::Done);
        order.push(id.to_string());
        Ok(())
    }
    let mut marks = BTreeMap::new();
    let mut order = Vec::new();
    for id in formulas.keys() {
        visit(id, formulas, &mut marks, &mut Vec::new(), &mut order)?;
    }
    Ok(order)
}

// ---- tokens -----------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Number(Decimal),
    Field(String),
    Name(String),
    Op(char),
    Cmp(CmpOp),
    LParen,
    RParen,
    Comma,
}

fn tokenize(text: &str) -> Result<Vec<(usize, Token)>, FormulaError> {
    let mut tokens = Vec::new();
    let mut chars = text.char_indices().peekable();
    let syntax = |at, reason| FormulaError::Syntax { at, reason };
    while let Some(&(at, c)) = chars.peek() {
        let token = match c {
            c if c.is_whitespace() => {
                chars.next();
                continue;
            }
            '0'..='9' => {
                let mut end = at;
                while let Some(&(i, d)) = chars.peek() {
                    if d.is_ascii_digit() || d == '.' {
                        end = i + 1;
                        chars.next();
                    } else {
                        break;
                    }
                }
                let n = Decimal::parse(&text[at..end]).map_err(|e| match e {
                    DecimalError::Invalid => syntax(at, "not a number"),
                    other => FormulaError::Arithmetic(other),
                })?;
                Token::Number(n)
            }
            '{' => {
                chars.next();
                let mut id = String::new();
                loop {
                    match chars.next() {
                        Some((_, '}')) => break,
                        Some((_, '{')) | None => {
                            return Err(syntax(at, "unclosed field reference"))
                        }
                        Some((_, ch)) => id.push(ch),
                    }
                }
                if id.is_empty() {
                    return Err(syntax(at, "empty field reference"));
                }
                Token::Field(id)
            }
            c if c.is_ascii_alphabetic() => {
                let mut name = String::new();
                while let Some(&(_, ch)) = chars.peek() {
                    if ch.is_ascii_alphanumeric() || ch == '_' {
                        name.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                Token::Name(name)
            }
            _ => {
                chars.next();
                let next = chars.peek().map(|&(_, n)| n);
                let mut two = |t| {
                    chars.next();
                    t
                };
                match (c, next) {
                    ('+', _) => Token::Op('+'),
                    ('-' | '−', _) => Token::Op('-'),
                    ('*' | '×', _) => Token::Op('*'),
                    ('/' | '÷', _) => Token::Op('/'),
                    ('(', _) => Token::LParen,
                    (')', _) => Token::RParen,
                    (',', _) => Token::Comma,
                    ('=', Some('=')) => two(Token::Cmp(CmpOp::Eq)),
                    ('=', _) => Token::Cmp(CmpOp::Eq),
                    ('!', Some('=')) => two(Token::Cmp(CmpOp::Ne)),
                    ('<', Some('>')) => two(Token::Cmp(CmpOp::Ne)),
                    ('<', Some('=')) => two(Token::Cmp(CmpOp::Le)),
                    ('<', _) => Token::Cmp(CmpOp::Lt),
                    ('>', Some('=')) => two(Token::Cmp(CmpOp::Ge)),
                    ('>', _) => Token::Cmp(CmpOp::Gt),
                    _ => return Err(syntax(at, "unexpected character")),
                }
            }
        };
        tokens.push((at, token));
    }
    Ok(tokens)
}

// ---- parser -----------------------------------------------------------------------------------

struct Parser<'a> {
    tokens: &'a [(usize, Token)],
    pos: usize,
    depth: usize,
    end: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|(_, t)| t)
    }

    fn at(&self) -> usize {
        self.tokens.get(self.pos).map_or(self.end, |(at, _)| *at)
    }

    fn error(&self, reason: &'static str) -> FormulaError {
        FormulaError::Syntax {
            at: self.at(),
            reason,
        }
    }

    fn deeper(&mut self) -> Result<(), FormulaError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(FormulaError::TooDeep);
        }
        Ok(())
    }

    /// comparison := additive (cmp additive)?
    fn expr(&mut self) -> Result<Expr, FormulaError> {
        let left = self.additive()?;
        if let Some(Token::Cmp(op)) = self.peek() {
            let op = *op;
            self.pos += 1;
            let right = self.additive()?;
            if let Some(Token::Cmp(_)) = self.peek() {
                return Err(self.error("comparisons cannot be chained; use and()"));
            }
            return Ok(Expr::Compare(op, Box::new(left), Box::new(right)));
        }
        Ok(left)
    }

    /// additive := term (('+' | '-') term)*
    fn additive(&mut self) -> Result<Expr, FormulaError> {
        let mut left = self.term()?;
        while let Some(Token::Op(c @ ('+' | '-'))) = self.peek() {
            let op = if *c == '+' { BinOp::Add } else { BinOp::Sub };
            self.pos += 1;
            let right = self.term()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    /// term := unary (('*' | '/') unary)*
    fn term(&mut self) -> Result<Expr, FormulaError> {
        let mut left = self.unary()?;
        while let Some(Token::Op(c @ ('*' | '/'))) = self.peek() {
            let op = if *c == '*' { BinOp::Mul } else { BinOp::Div };
            self.pos += 1;
            let right = self.unary()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    /// unary := '-' unary | primary
    fn unary(&mut self) -> Result<Expr, FormulaError> {
        if let Some(Token::Op('-')) = self.peek() {
            self.pos += 1;
            self.deeper()?;
            let inner = self.unary()?;
            self.depth -= 1;
            return Ok(Expr::Neg(Box::new(inner)));
        }
        self.primary()
    }

    /// primary := number | field | name '(' args ')' | '(' expr ')'
    fn primary(&mut self) -> Result<Expr, FormulaError> {
        let at = self.at();
        let Some(token) = self.peek().cloned() else {
            return Err(self.error("the formula ends too early"));
        };
        self.pos += 1;
        match token {
            Token::Number(n) => Ok(Expr::Number(n)),
            Token::Field(id) => Ok(Expr::Field(id)),
            Token::LParen => {
                self.deeper()?;
                let inner = self.expr()?;
                self.depth -= 1;
                self.expect(Token::RParen, "a closing parenthesis is missing")?;
                Ok(inner)
            }
            Token::Name(name) => {
                let func = Func::from_name(&name).ok_or(FormulaError::UnknownFunction(name))?;
                self.expect(Token::LParen, "a function name must be followed by (")?;
                self.deeper()?;
                let mut args = Vec::new();
                if self.peek() != Some(&Token::RParen) {
                    loop {
                        args.push(self.expr()?);
                        if self.peek() == Some(&Token::Comma) {
                            self.pos += 1;
                        } else {
                            break;
                        }
                    }
                }
                self.depth -= 1;
                self.expect(Token::RParen, "a closing parenthesis is missing")?;
                let arity_ok = match func {
                    Func::Sum | Func::Min | Func::Max | Func::And | Func::Or => !args.is_empty(),
                    Func::Round => args.len() == 2,
                    Func::If => args.len() == 3,
                    Func::Not => args.len() == 1,
                };
                if !arity_ok {
                    return Err(FormulaError::Arguments(func.name()));
                }
                Ok(Expr::Call(func, args))
            }
            _ => Err(FormulaError::Syntax {
                at,
                reason: "a number, a field or a function is expected",
            }),
        }
    }

    fn expect(&mut self, token: Token, reason: &'static str) -> Result<(), FormulaError> {
        if self.peek() == Some(&token) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.error(reason))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Number,
    Bool,
}

/// Checks that numbers and conditions are used where they belong, before any value is known.
fn kind_of(expr: &Expr) -> Result<Kind, FormulaError> {
    let number = |e: &Expr| match kind_of(e)? {
        Kind::Number => Ok(()),
        Kind::Bool => Err(FormulaError::Type("a number is needed, not a condition")),
    };
    let condition = |e: &Expr| match kind_of(e)? {
        Kind::Bool => Ok(()),
        Kind::Number => Err(FormulaError::Type("a condition is needed, not a number")),
    };
    Ok(match expr {
        Expr::Number(_) | Expr::Field(_) => Kind::Number,
        Expr::Neg(e) => {
            number(e)?;
            Kind::Number
        }
        Expr::Binary(_, a, b) | Expr::Compare(_, a, b) => {
            number(a)?;
            number(b)?;
            if matches!(expr, Expr::Compare(..)) {
                Kind::Bool
            } else {
                Kind::Number
            }
        }
        Expr::Call(func, args) => match func {
            Func::Sum | Func::Min | Func::Max | Func::Round => {
                args.iter().try_for_each(number)?;
                Kind::Number
            }
            Func::And | Func::Or | Func::Not => {
                args.iter().try_for_each(condition)?;
                Kind::Bool
            }
            Func::If => {
                condition(&args[0])?;
                let (a, b) = (kind_of(&args[1])?, kind_of(&args[2])?);
                if a != b {
                    return Err(FormulaError::Type("both branches of if() must be numbers"));
                }
                a
            }
        },
    })
}

fn collect_fields(expr: &Expr, out: &mut Vec<String>) {
    match expr {
        Expr::Number(_) => {}
        Expr::Field(id) => {
            if !out.contains(id) {
                out.push(id.clone());
            }
        }
        Expr::Neg(e) => collect_fields(e, out),
        Expr::Binary(_, a, b) | Expr::Compare(_, a, b) => {
            collect_fields(a, out);
            collect_fields(b, out);
        }
        Expr::Call(_, args) => args.iter().for_each(|a| collect_fields(a, out)),
    }
}

// ---- evaluation -------------------------------------------------------------------------------

fn eval(expr: &Expr, value_of: &dyn Fn(&str) -> Option<Decimal>) -> Result<Value, FormulaError> {
    let num = |e: &Expr| eval(e, value_of)?.number();
    let truth = |e: &Expr| eval(e, value_of)?.truth();
    Ok(match expr {
        Expr::Number(n) => Value::Number(*n),
        Expr::Field(id) => {
            Value::Number(value_of(id).ok_or_else(|| FormulaError::UnknownField(id.clone()))?)
        }
        Expr::Neg(e) => Value::Number(-num(e)?),
        Expr::Binary(op, a, b) => {
            let (a, b) = (num(a)?, num(b)?);
            Value::Number(match op {
                BinOp::Add => a.checked_add(&b)?,
                BinOp::Sub => a.checked_sub(&b)?,
                BinOp::Mul => a.checked_mul(&b)?,
                BinOp::Div => a.checked_div(&b, MAX_SCALE)?,
            })
        }
        Expr::Compare(op, a, b) => {
            let (a, b) = (num(a)?, num(b)?);
            Value::Bool(match op {
                CmpOp::Eq => a == b,
                CmpOp::Ne => a != b,
                CmpOp::Lt => a < b,
                CmpOp::Le => a <= b,
                CmpOp::Gt => a > b,
                CmpOp::Ge => a >= b,
            })
        }
        Expr::Call(func, args) => match func {
            Func::Sum => {
                let mut total = Decimal::ZERO;
                for a in args {
                    total = total.checked_add(&num(a)?)?;
                }
                Value::Number(total)
            }
            Func::Min | Func::Max => {
                let mut best = num(&args[0])?;
                for a in &args[1..] {
                    let v = num(a)?;
                    if (*func == Func::Min && v < best) || (*func == Func::Max && v > best) {
                        best = v;
                    }
                }
                Value::Number(best)
            }
            Func::Round => {
                let places = num(&args[1])?;
                let places = u8::try_from(places.normalized().mantissa())
                    .ok()
                    .filter(|p| places.decimal_places() == 0 && *p <= MAX_SCALE)
                    .ok_or(FormulaError::Arguments("round"))?;
                Value::Number(num(&args[0])?.round(places)?)
            }
            Func::If => {
                if truth(&args[0])? {
                    eval(&args[1], value_of)?
                } else {
                    eval(&args[2], value_of)?
                }
            }
            Func::And => {
                let mut all = true;
                for a in args {
                    all &= truth(a)?;
                }
                Value::Bool(all)
            }
            Func::Or => {
                let mut any = false;
                for a in args {
                    any |= truth(a)?;
                }
                Value::Bool(any)
            }
            Func::Not => Value::Bool(!truth(&args[0])?),
        },
    })
}

/// The fields a set of formulas read that are not themselves formulas: the inputs a page must
/// collect before it can show every result.
pub fn inputs(formulas: &BTreeMap<String, Formula>) -> BTreeSet<String> {
    formulas
        .values()
        .flat_map(|f| f.fields().iter())
        .filter(|id| !formulas.contains_key(*id))
        .cloned()
        .collect()
}

// ---- formula fields in the envelope -----------------------------------------------------------

/// A formula field's sealed formula (envelope schema version 8, the field's `formula`). Part of the
/// prepared terms.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FormulaSpec {
    /// The formula, in this module's language, at most [`MAX_FORMULA_LEN`] bytes.
    pub expr: String,
    /// For each dropdown (by field id) and radio group (by group name) the formula reads, the
    /// number each of its options counts as: option text (a radio option's caption) → decimal
    /// text such as `12.5`. Always written, `{}` when the formula reads no choice.
    #[serde(default)]
    pub map: BTreeMap<String, BTreeMap<String, String>>,
}

/// Code: a formula reads a field that holds no number (text, a date, a signature, one radio
/// option rather than its group).
pub const CODE_INPUT_TYPE: &str = "formula_input_type";
/// Code: a formula reads a field filled by a later signer (or, under a parallel policy, by
/// another signer).
pub const CODE_LATER_INPUT: &str = "formula_later_input";
/// Code: a formula's option map is wrong: an option without a number, a number that is not a
/// decimal, or an entry for something the formula does not read as a choice.
pub const CODE_MAP: &str = "formula_map";

/// Why a formula field cannot be prepared or computed: the formula field, a stable code
/// ([`FormulaError::code`], a [`DecimalError`] or [`crate::FormatError`] code, or one of the
/// `CODE_*` constants of this module) and an English sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormulaFieldError {
    /// The id of the formula field.
    pub field: String,
    /// A stable code, catalogued in [`crate::messages`].
    pub code: &'static str,
    /// What is wrong, in English (it follows "formula field X ").
    pub message: String,
}

impl fmt::Display for FormulaFieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "formula field {} {}", self.field, self.message)
    }
}

impl std::error::Error for FormulaFieldError {}

/// What a formula's reference reads.
enum Input<'a> {
    Number(&'a Field),
    Checkbox(&'a Field),
    Formula(&'a Field),
    Dropdown(&'a Field),
    /// A radio group: its options, in document order.
    Radio(Vec<&'a Field>),
}

impl Input<'_> {
    /// The signer who answers it.
    fn signer(&self) -> &str {
        match self {
            Input::Number(f) | Input::Checkbox(f) | Input::Formula(f) | Input::Dropdown(f) => {
                &f.assigned_signer
            }
            Input::Radio(options) => &options[0].assigned_signer,
        }
    }

    /// A dropdown's options or a radio group's captions (trimmed); `None` for a plain number.
    fn choices(&self) -> Option<Vec<&str>> {
        match self {
            Input::Dropdown(f) => Some(
                f.options
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(String::as_str)
                    .collect(),
            ),
            Input::Radio(options) => Some(
                options
                    .iter()
                    .map(|o| o.label.as_deref().unwrap_or_default().trim())
                    .collect(),
            ),
            _ => None,
        }
    }
}

/// What `reference` names among `fields`: a field by id first, else a radio group by name.
fn input<'a>(fields: &'a [Field], reference: &str) -> Result<Input<'a>, (&'static str, String)> {
    if let Some(f) = fields.iter().find(|f| f.id == reference) {
        return match f.field_type {
            FieldType::Number => Ok(Input::Number(f)),
            FieldType::Checkbox => Ok(Input::Checkbox(f)),
            FieldType::Formula => Ok(Input::Formula(f)),
            FieldType::Dropdown => Ok(Input::Dropdown(f)),
            FieldType::Radio => Err((
                CODE_INPUT_TYPE,
                format!(
                    "reads {{{reference}}}, one option of a radio group: a formula reads the \
                     group by its name"
                ),
            )),
            _ => Err((
                CODE_INPUT_TYPE,
                format!("reads {{{reference}}}, which holds no number"),
            )),
        };
    }
    let group: Vec<&Field> = fields
        .iter()
        .filter(|f| f.field_type == FieldType::Radio && f.group.as_deref() == Some(reference))
        .collect();
    if group.is_empty() {
        Err((
            "formula_unknown_field",
            format!("reads {{{reference}}}, which is neither a field nor a radio group"),
        ))
    } else {
        Ok(Input::Radio(group))
    }
}

/// The formula of every formula field, parsed.
fn parsed(fields: &[Field]) -> Result<BTreeMap<String, Formula>, FormulaFieldError> {
    let mut out = BTreeMap::new();
    for f in fields.iter().filter(|f| f.field_type == FieldType::Formula) {
        let fail = |code, message| FormulaFieldError {
            field: f.id.clone(),
            code,
            message,
        };
        let spec = f
            .formula
            .as_ref()
            .ok_or_else(|| fail("formula_syntax", "has no formula".into()))?;
        let formula = Formula::parse(&spec.expr)
            .map_err(|e| fail(e.code(), format!("has a formula that cannot be read: {e}")))?;
        out.insert(f.id.clone(), formula);
    }
    Ok(out)
}

/// The order in which the formula fields are computed, or the loop that prevents it.
fn ordered(formulas: &BTreeMap<String, Formula>) -> Result<Vec<String>, FormulaFieldError> {
    evaluation_order(formulas).map_err(|e| FormulaFieldError {
        field: match &e {
            FormulaError::Loop(ids) => ids.first().cloned().unwrap_or_default(),
            _ => String::new(),
        },
        code: e.code(),
        message: format!("cannot be computed: {e}"),
    })
}

/// The preparation rules of the formula fields among `fields` (see the module documentation):
/// readable formulas, known inputs that hold numbers, filled by the formula's own signer or by an
/// earlier one (a lower `order` under a sequential policy; under a parallel policy only the
/// formula's own signer), a number for every option of each choice read and no other map
/// entries, and no loops. `order_of` gives a signer's 1-based `order` by id. `formula` members
/// on other fields are the caller's to refuse.
pub fn check_formula_fields(
    fields: &[Field],
    order_of: impl Fn(&str) -> Option<u32>,
    signing_order: SigningOrder,
) -> Result<(), FormulaFieldError> {
    let formulas = parsed(fields)?;
    for f in fields.iter().filter(|f| f.field_type == FieldType::Formula) {
        let fail = |code, message| FormulaFieldError {
            field: f.id.clone(),
            code,
            message,
        };
        let spec = f.formula.as_ref().expect("parsed above");
        let formula = &formulas[&f.id];
        for reference in formula.fields() {
            let read = input(fields, reference).map_err(|(code, m)| fail(code, m))?;
            let by = read.signer();
            let earlier = signing_order == SigningOrder::Sequential
                && matches!((order_of(by), order_of(&f.assigned_signer)),
                    (Some(a), Some(b)) if a < b);
            if by != f.assigned_signer && !earlier {
                return Err(fail(
                    CODE_LATER_INPUT,
                    format!(
                        "reads {{{reference}}}, which signer {by} fills: a formula reads only \
                         fields of its own signer or of a signer who signs before"
                    ),
                ));
            }
            let Some(choices) = read.choices() else {
                continue;
            };
            let numbers = spec.map.get(reference);
            for choice in &choices {
                let number = numbers.and_then(|n| n.get(*choice)).ok_or_else(|| {
                    fail(
                        CODE_MAP,
                        format!("gives no number for option '{choice}' of {{{reference}}}"),
                    )
                })?;
                Decimal::parse(number).map_err(|_| {
                    fail(
                        CODE_MAP,
                        format!(
                            "gives option '{choice}' of {{{reference}}} the number '{number}', \
                             not a decimal written like -1234.5"
                        ),
                    )
                })?;
            }
            if let Some(extra) = numbers
                .into_iter()
                .flat_map(|n| n.keys())
                .find(|k| !choices.contains(&k.as_str()))
            {
                return Err(fail(
                    CODE_MAP,
                    format!(
                        "gives a number for '{extra}', which is not an option of {{{reference}}}"
                    ),
                ));
            }
        }
        for key in spec.map.keys() {
            let is_choice = formula.fields().contains(key)
                && input(fields, key).is_ok_and(|i| i.choices().is_some());
            if !is_choice {
                return Err(fail(
                    CODE_MAP,
                    format!(
                        "has numbers for '{key}', which the formula does not read as a dropdown \
                         or radio group"
                    ),
                ));
            }
        }
    }
    ordered(&formulas)?;
    Ok(())
}

/// Compute formula fields. `compute` picks the formula fields to compute; every other field,
/// formula fields not picked included, counts with its value from `given` (by field id; a radio
/// option's `true` or `false`) or, when `given` has none, its value in `fields`. Returns each
/// computed field's value as the envelope stores it: canonical, with the field's decimal places.
///
/// The signing engine computes the signer's formulas from the values they gave, the verifier
/// computes them again from the revision, and a host computes them for its live display: all
/// with this function. Errors name the formula field and a stable code: a division by zero, a
/// number out of range, a choice without a number.
pub fn compute_formula_fields(
    fields: &[Field],
    given: &BTreeMap<String, String>,
    compute: impl Fn(&Field) -> bool,
) -> Result<BTreeMap<String, String>, FormulaFieldError> {
    let formulas = parsed(fields)?;
    let mut results: BTreeMap<String, String> = BTreeMap::new();
    for id in ordered(&formulas)? {
        let f = fields.iter().find(|f| f.id == id).expect("a formula field");
        if !compute(f) {
            continue;
        }
        let fail = |code, message| FormulaFieldError {
            field: f.id.clone(),
            code,
            message,
        };
        let stored = |x: &Field| -> String {
            results
                .get(&x.id)
                .or_else(|| given.get(&x.id))
                .map(String::as_str)
                .or(x.value.as_deref())
                .unwrap_or_default()
                .trim()
                .to_string()
        };
        let empty_map = BTreeMap::new();
        let map = &f.formula.as_ref().expect("parsed").map;
        let mut values: BTreeMap<&str, Decimal> = BTreeMap::new();
        for reference in formulas[&id].fields() {
            let read = input(fields, reference).map_err(|(code, m)| fail(code, m))?;
            let chosen = match &read {
                Input::Number(x) | Input::Formula(x) => {
                    let v = stored(x);
                    let n = if v.is_empty() {
                        Decimal::ZERO
                    } else {
                        Decimal::parse(&v).map_err(|e| {
                            fail(
                                e.code(),
                                format!("reads {{{reference}}}, which holds no number"),
                            )
                        })?
                    };
                    values.insert(reference, n);
                    continue;
                }
                Input::Checkbox(x) => {
                    let ticked = stored(x).eq_ignore_ascii_case("true");
                    let n = if ticked { Decimal::ONE } else { Decimal::ZERO };
                    values.insert(reference, n);
                    continue;
                }
                Input::Dropdown(x) => Some(stored(x)).filter(|v| !v.is_empty()),
                Input::Radio(options) => options
                    .iter()
                    .find(|o| stored(o).eq_ignore_ascii_case("true"))
                    .map(|o| o.label.as_deref().unwrap_or_default().trim().to_string()),
            };
            let n = match chosen {
                None => Decimal::ZERO,
                Some(choice) => {
                    let number = map
                        .get(reference)
                        .unwrap_or(&empty_map)
                        .get(&choice)
                        .ok_or_else(|| {
                            fail(
                                CODE_MAP,
                                format!("gives no number for option '{choice}' of {{{reference}}}"),
                            )
                        })?;
                    Decimal::parse(number).map_err(|_| {
                        fail(
                            CODE_MAP,
                            format!("gives option '{choice}' of {{{reference}}} no decimal number"),
                        )
                    })?
                }
            };
            values.insert(reference, n);
        }
        let result = formulas[&id]
            .evaluate(|r| values.get(r).copied())
            .map_err(|e| fail(e.code(), format!("cannot be computed: {e}")))?;
        let number_format = f.number_format.clone().unwrap_or_default();
        let rounded = result
            .round(number_format.decimals)
            .map_err(|e| fail(e.code(), format!("cannot be computed: {e}")))?;
        let canonical = number_format.check(&rounded.to_string()).map_err(|e| {
            fail(
                e.code(),
                format!("computes {rounded}, which its number format does not take"),
            )
        })?;
        results.insert(id, canonical);
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Decimal {
        Decimal::parse(s).unwrap()
    }

    fn eval_with(text: &str, values: &[(&str, &str)]) -> Result<String, FormulaError> {
        let formula = Formula::parse(text)?;
        let map: BTreeMap<&str, Decimal> = values.iter().map(|(k, v)| (*k, d(v))).collect();
        formula
            .evaluate(|id| map.get(id).copied())
            .map(|v| v.to_string())
    }

    fn ok(text: &str, values: &[(&str, &str)]) -> String {
        eval_with(text, values).unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    #[test]
    fn arithmetic_with_precedence() {
        assert_eq!(ok("1 + 2 * 3", &[]), "7");
        assert_eq!(ok("(1 + 2) * 3", &[]), "9");
        assert_eq!(ok("10 - 4 - 3", &[]), "3");
        assert_eq!(ok("2 * -3", &[]), "-6");
        assert_eq!(ok("--2", &[]), "2");
        assert_eq!(ok("0.1 + 0.2", &[]), "0.3");
        assert_eq!(ok("7 × 6 − 2 ÷ 4", &[]), "41.500000000000000000");
        assert_eq!(ok("round(1 / 3, 4)", &[]), "0.3333");
        assert_eq!(ok("round(2 / 3, 2)", &[]), "0.67");
        assert_eq!(ok("round(-2.5, 0)", &[]), "-3");
    }

    #[test]
    fn fields_and_functions() {
        let order = [("quantity", "3"), ("unit_price", "19.99"), ("express", "1")];
        assert_eq!(ok("{quantity} * {unit_price}", &order), "59.97");
        assert_eq!(
            ok(
                "{quantity} * {unit_price} + if({express} = 1, 15, 0)",
                &order
            ),
            "74.97"
        );
        assert_eq!(ok("SUM({quantity}, 2, 0.5)", &order), "5.5");
        assert_eq!(ok("min(4, {quantity}, 7)", &order), "3");
        assert_eq!(ok("Max(4, {quantity}, 7)", &order), "7");
        assert_eq!(ok("round(sum({unit_price}, 0.005), 2)", &order), "20.00");
        assert_eq!(
            ok(
                "if(and({quantity} >= 3, not({express} <> 1)), 10, 0)",
                &order
            ),
            "10"
        );
        assert_eq!(
            ok("if(or({quantity} < 3, {express} != 1), 10, 0)", &order),
            "0"
        );
        assert_eq!(
            ok(
                "if({quantity} <= 3, 1, 0) + if({quantity} > 3, 1, 0)",
                &order
            ),
            "1"
        );
        // Ids may hold any character but braces.
        assert_eq!(ok("{line 1 / net} * 2", &[("line 1 / net", "4.5")]), "9.0");
    }

    #[test]
    fn fields_are_listed_once_in_order() {
        let f = Formula::parse("{b} + {a} * {b} + if({c} > 0, {a}, 0)").unwrap();
        assert_eq!(f.fields(), ["b", "a", "c"]);
    }

    #[test]
    fn if_evaluates_only_the_branch_it_takes() {
        assert_eq!(ok("if({n} = 0, 0, 100 / {n})", &[("n", "0")]), "0");
        assert_eq!(
            eval_with("if({n} = 0, 100 / {n}, 0)", &[("n", "0")]),
            Err(FormulaError::Arithmetic(DecimalError::DivisionByZero))
        );
    }

    #[test]
    fn runtime_errors_are_errors() {
        assert_eq!(
            eval_with("1 / 0", &[]),
            Err(FormulaError::Arithmetic(DecimalError::DivisionByZero))
        );
        assert_eq!(
            eval_with("999999999999999999 + 1", &[]),
            Err(FormulaError::Arithmetic(DecimalError::TooLarge))
        );
        assert_eq!(
            eval_with("{missing} + 1", &[]),
            Err(FormulaError::UnknownField("missing".into()))
        );
        assert_eq!(
            eval_with("round(1.5, 1.5)", &[]),
            Err(FormulaError::Arguments("round"))
        );
        assert_eq!(
            eval_with("round(1.5, -1)", &[]),
            Err(FormulaError::Arguments("round"))
        );
        assert_eq!(
            eval_with("round(1.5, 19)", &[]),
            Err(FormulaError::Arguments("round"))
        );
        assert_eq!(ok("round(1.5, 2.0)", &[]), "1.50");
    }

    #[test]
    fn malformed_formulas_are_refused() {
        let syntax = |text: &str| match Formula::parse(text) {
            Err(FormulaError::Syntax { .. }) => {}
            other => panic!("{text}: {other:?}"),
        };
        for text in [
            "",
            "1 +",
            "(1 + 2",
            "1 + 2)",
            "1 2",
            "{a",
            "{}",
            "{a{b}}",
            "1 $ 2",
            "1 < 2 < 3",
            "sum 1",
            "sum(1,)",
            "sum(,1)",
            "05",
            "1.",
            "1..2",
            "1.2.3",
            ",",
            "max(1 2)",
        ] {
            syntax(text);
        }
        assert_eq!(
            Formula::parse("pow(2, 3)"),
            Err(FormulaError::UnknownFunction("pow".into()))
        );
        for text in [
            "sum()",
            "round(1)",
            "if(1 > 0, 2)",
            "not(1 > 0, 2 > 0)",
            "and()",
        ] {
            assert!(
                matches!(Formula::parse(text), Err(FormulaError::Arguments(_))),
                "{text}"
            );
        }
        for text in [
            "1 > 0",
            "if(1, 2, 3)",
            "and(1, 2 > 0)",
            "(1 > 0) + 1",
            "sum(1 > 0)",
            "if(1 > 0, 1, 2 > 0)",
            "-(1 > 0)",
            "(1 > 0) = (2 > 0)",
        ] {
            assert!(
                matches!(Formula::parse(text), Err(FormulaError::Type(_))),
                "{text}"
            );
        }
    }

    #[test]
    fn size_and_depth_are_limited() {
        assert_eq!(
            Formula::parse(&"1+".repeat(MAX_FORMULA_LEN)),
            Err(FormulaError::TooLong)
        );
        let deep = format!(
            "{}1{}",
            "(".repeat(MAX_DEPTH + 1),
            ")".repeat(MAX_DEPTH + 1)
        );
        assert_eq!(Formula::parse(&deep), Err(FormulaError::TooDeep));
        let ok_depth = format!("{}1{}", "(".repeat(MAX_DEPTH), ")".repeat(MAX_DEPTH));
        assert!(Formula::parse(&ok_depth).is_ok());
        assert_eq!(
            Formula::parse(&"-".repeat(MAX_DEPTH + 1)),
            Err(FormulaError::TooDeep)
        );
        let nested_calls = format!(
            "{}1{}",
            "sum(".repeat(MAX_DEPTH + 1),
            ")".repeat(MAX_DEPTH + 1)
        );
        assert_eq!(Formula::parse(&nested_calls), Err(FormulaError::TooDeep));
    }

    #[test]
    fn formulas_are_ordered_and_loops_refused() {
        let set = |pairs: &[(&str, &str)]| -> BTreeMap<String, Formula> {
            pairs
                .iter()
                .map(|(id, text)| (id.to_string(), Formula::parse(text).unwrap()))
                .collect()
        };
        let formulas = set(&[
            ("total", "{subtotal} + {tax}"),
            ("tax", "round({subtotal} * 0.2, 2)"),
            ("subtotal", "{qty} * {price}"),
        ]);
        assert_eq!(
            evaluation_order(&formulas).unwrap(),
            ["subtotal", "tax", "total"]
        );
        assert_eq!(
            inputs(&formulas).into_iter().collect::<Vec<_>>(),
            ["price", "qty"]
        );
        let looped = set(&[
            ("a", "{b} + 1"),
            ("b", "{c} + 1"),
            ("c", "{a} + 1"),
            ("d", "1"),
        ]);
        assert_eq!(
            evaluation_order(&looped),
            Err(FormulaError::Loop(vec![
                "a".into(),
                "b".into(),
                "c".into(),
                "a".into()
            ]))
        );
        let self_loop = set(&[("a", "{a} + 1")]);
        assert_eq!(
            evaluation_order(&self_loop),
            Err(FormulaError::Loop(vec!["a".into(), "a".into()]))
        );
    }
}
