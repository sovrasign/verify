//! Custom patterns for text fields: a small, safe subset of regular expressions that a preparer
//! seals into a field's `value_format` (`{"kind": "pattern", "pattern": "PO-\\d{4}-\\d{3}"}`, from
//! envelope schema version 8).
//!
//! The signer's page, the engine at signing and the verifier all run this matcher, so a value is
//! accepted or refused the same way everywhere. It is written here (no regular-expression crate)
//! so that its behaviour is fixed by this file and needs no further supply-chain audit.
//!
//! ## What a pattern may contain
//!
//! * The whole value must match: a pattern is always anchored at both ends. A leading `^` and a
//!   trailing `$` are accepted and change nothing; anywhere else they are refused.
//! * Literal characters; `.` (any character but a line break); escapes `\d` (an ASCII digit),
//!   `\w` (an ASCII letter, digit or `_`), `\s` (white space) and their negations `\D`, `\W`,
//!   `\S`; `\n`, `\t`; and `\` before any ASCII punctuation for that character itself.
//! * Classes `[a-z0-9_]` and negated classes `[^...]`, with ranges, the escapes above and a `-`
//!   first or last. A `[` or `]` inside a class must be escaped.
//! * Groups `(...)` and `(?:...)`, alternatives `a|b`, and the quantifiers `*`, `+`, `?`,
//!   `{n}`, `{n,}` and `{n,m}` (counts up to [`MAX_REPEAT`]).
//!
//! Refused: back-references (`\1`), look-around and every other `(?...)` group, lazy or
//! possessive quantifiers (`*?`, `*+`), other escapes (`\b`, `\p{...}`...), patterns longer than
//! [`MAX_PATTERN_CHARS`] characters, and patterns whose compiled program would exceed
//! [`MAX_PROGRAM`] steps.
//!
//! ## Linear time
//!
//! A pattern compiles to a small automaton (a Thompson NFA) that is run over the value once,
//! keeping the set of states it can be in. The work is at most the value's length times the
//! program's size ([`MAX_PROGRAM`]), whatever the pattern and the value: no backtracking, so no
//! pattern can make a page or the verifier hang.

use std::fmt;

/// Longest pattern accepted, in characters.
pub const MAX_PATTERN_CHARS: usize = 200;

/// Largest count in a `{n,m}` quantifier.
pub const MAX_REPEAT: u32 = 1000;

/// Most steps a compiled pattern may have (counted repeats are expanded, so `\d{4}` is four).
pub const MAX_PROGRAM: usize = 2000;

/// Why a pattern is refused at preparation (an English sentence for the preparer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternError(String);

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PatternError {}

fn err<T>(msg: impl Into<String>) -> Result<T, PatternError> {
    Err(PatternError(msg.into()))
}

/// A compiled custom pattern. Compare with [`Pattern::source`]: two patterns are equal when
/// their source text is.
#[derive(Debug, Clone)]
pub struct Pattern {
    source: String,
    program: Vec<Inst>,
}

impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

impl Eq for Pattern {}

impl Pattern {
    /// Compile `source`, or say why it is refused.
    pub fn new(source: &str) -> Result<Pattern, PatternError> {
        if source.is_empty() {
            return err("the pattern is empty");
        }
        if source.chars().count() > MAX_PATTERN_CHARS {
            return err(format!(
                "the pattern is longer than {MAX_PATTERN_CHARS} characters"
            ));
        }
        if source.chars().any(char::is_control) {
            return err("the pattern contains a control character");
        }
        let mut body = source.strip_prefix('^').unwrap_or(source);
        // A trailing `$` is an anchor unless it is escaped (`\$`).
        if body.ends_with('$') && !ends_with_escape(&body[..body.len() - 1]) {
            body = &body[..body.len() - 1];
        }
        let chars: Vec<char> = body.chars().collect();
        let mut parser = Parser {
            chars: &chars,
            pos: 0,
        };
        let node = parser.alternation()?;
        if parser.pos != chars.len() {
            // Only an unmatched `)` stops the top-level parse early.
            return err("the pattern has a ')' without its '('");
        }
        if node.size() > MAX_PROGRAM {
            return err(format!(
                "the pattern is too complex (its repeats expand to more than {MAX_PROGRAM} steps)"
            ));
        }
        let mut program = Vec::new();
        compile(&node, &mut program);
        program.push(Inst::Match);
        Ok(Pattern {
            source: source.to_string(),
            program,
        })
    }

    /// The pattern as the preparer wrote it.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Whether the whole of `value` matches.
    pub fn is_match(&self, value: &str) -> bool {
        let n = self.program.len();
        let mut current = States::new(n);
        let mut next = States::new(n);
        let mut stack = Vec::new();
        current.add(&self.program, 0, &mut stack);
        for c in value.chars() {
            next.clear();
            for &pc in &current.list {
                if let Inst::Char(m) = &self.program[pc] {
                    if m.matches(c) {
                        next.add(&self.program, pc + 1, &mut stack);
                    }
                }
            }
            std::mem::swap(&mut current, &mut next);
            if current.list.is_empty() {
                return false;
            }
        }
        current
            .list
            .iter()
            .any(|&pc| matches!(self.program[pc], Inst::Match))
    }
}

/// Whether `s` ends with an odd number of backslashes (so the next character is escaped).
fn ends_with_escape(s: &str) -> bool {
    s.chars().rev().take_while(|&c| c == '\\').count() % 2 == 1
}

// ---- syntax -----------------------------------------------------------------------------------

/// One character test.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Matcher {
    Literal(char),
    /// `.`: anything but a line break.
    Any,
    Class {
        items: Vec<ClassItem>,
        negated: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClassItem {
    Range(char, char),
    Digit(bool),
    Word(bool),
    Space(bool),
}

impl ClassItem {
    fn matches(self, c: char) -> bool {
        match self {
            ClassItem::Range(lo, hi) => lo <= c && c <= hi,
            ClassItem::Digit(yes) => c.is_ascii_digit() == yes,
            ClassItem::Word(yes) => (c.is_ascii_alphanumeric() || c == '_') == yes,
            ClassItem::Space(yes) => c.is_whitespace() == yes,
        }
    }
}

impl Matcher {
    fn matches(&self, c: char) -> bool {
        match self {
            Matcher::Literal(l) => *l == c,
            Matcher::Any => c != '\n' && c != '\r',
            Matcher::Class { items, negated } => items.iter().any(|i| i.matches(c)) != *negated,
        }
    }
}

#[derive(Debug, Clone)]
enum Node {
    Empty,
    Char(Matcher),
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Repeat {
        node: Box<Node>,
        min: u32,
        max: Option<u32>,
    },
}

impl Node {
    /// The number of program steps [`compile`] emits for this node (saturating), so that a
    /// pattern is refused before an over-large program is built.
    fn size(&self) -> usize {
        match self {
            Node::Empty => 0,
            Node::Char(_) => 1,
            Node::Concat(nodes) => nodes.iter().fold(0, |acc, n| acc.saturating_add(n.size())),
            // A split and a jump per extra alternative.
            Node::Alt(nodes) => nodes.iter().fold(0usize, |acc, n| {
                acc.saturating_add(n.size()).saturating_add(2)
            }),
            Node::Repeat { node, min, max } => {
                let one = node.size();
                let fixed = one.saturating_mul(*min as usize);
                let extra = match max {
                    // A split and a jump around one more copy.
                    None => one.saturating_add(2),
                    Some(max) => one
                        .saturating_add(1)
                        .saturating_mul(max.saturating_sub(*min) as usize),
                };
                fixed.saturating_add(extra)
            }
        }
    }
}

struct Parser<'a> {
    chars: &'a [char],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// `a|b|c` (stops before a `)` or at the end).
    fn alternation(&mut self) -> Result<Node, PatternError> {
        let mut alternatives = vec![self.concatenation()?];
        while self.eat('|') {
            alternatives.push(self.concatenation()?);
        }
        Ok(if alternatives.len() == 1 {
            alternatives.pop().unwrap_or(Node::Empty)
        } else {
            Node::Alt(alternatives)
        })
    }

    fn concatenation(&mut self) -> Result<Node, PatternError> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            let atom = self.atom()?;
            items.push(self.quantified(atom)?);
        }
        Ok(match items.len() {
            0 => Node::Empty,
            1 => items.pop().unwrap_or(Node::Empty),
            _ => Node::Concat(items),
        })
    }

    fn atom(&mut self) -> Result<Node, PatternError> {
        let Some(c) = self.next() else {
            return err("the pattern ends too early");
        };
        Ok(match c {
            '(' => {
                if self.eat('?') && !self.eat(':') {
                    return err(
                        "the pattern uses a '(?' group: look-around, named groups and flags are \
                         not supported (only '(?:...)')",
                    );
                }
                let inner = self.alternation()?;
                if !self.eat(')') {
                    return err("the pattern has a '(' without its ')'");
                }
                inner
            }
            '[' => Node::Char(self.class()?),
            '.' => Node::Char(Matcher::Any),
            '\\' => Node::Char(self.escape(false)?),
            '*' | '+' | '?' | '{' => {
                return err(format!("the pattern has a '{c}' with nothing to repeat"));
            }
            ']' | '}' => {
                return err(format!(
                    "the pattern has a '{c}' that must be escaped as '\\{c}'"
                ));
            }
            '^' | '$' => {
                return err(format!(
                    "the pattern has a '{c}' inside it (the whole value always has to match; \
                     write '\\{c}' for the character itself)"
                ));
            }
            c => Node::Char(Matcher::Literal(c)),
        })
    }

    /// An escape after its `\`, inside a class or not.
    fn escape(&mut self, in_class: bool) -> Result<Matcher, PatternError> {
        let Some(c) = self.next() else {
            return err("the pattern ends with a lone '\\'");
        };
        let class = |item| Matcher::Class {
            items: vec![item],
            negated: false,
        };
        Ok(match c {
            'd' => class(ClassItem::Digit(true)),
            'D' => class(ClassItem::Digit(false)),
            'w' => class(ClassItem::Word(true)),
            'W' => class(ClassItem::Word(false)),
            's' => class(ClassItem::Space(true)),
            'S' => class(ClassItem::Space(false)),
            'n' => Matcher::Literal('\n'),
            't' => Matcher::Literal('\t'),
            c if c.is_ascii_punctuation() => Matcher::Literal(c),
            c if c.is_ascii_digit() => {
                return err("the pattern uses a back-reference, which is not supported");
            }
            c => {
                return err(format!(
                    "the pattern uses '\\{c}', which is not supported{}",
                    if in_class { " in a class" } else { "" }
                ));
            }
        })
    }

    /// A class after its `[`.
    fn class(&mut self) -> Result<Matcher, PatternError> {
        let negated = self.eat('^');
        let mut items = Vec::new();
        let mut first = true;
        loop {
            let Some(c) = self.next() else {
                return err("the pattern has a '[' without its ']'");
            };
            let single = match c {
                ']' if !first => break,
                ']' | '[' => {
                    return err(format!(
                        "the pattern has a '{c}' inside a class: escape it as '\\{c}'"
                    ));
                }
                '\\' => match self.escape(true)? {
                    Matcher::Literal(l) => l,
                    Matcher::Class { items: more, .. } => {
                        items.extend(more);
                        first = false;
                        continue;
                    }
                    Matcher::Any => unreachable!("an escape is never '.'"),
                },
                c => c,
            };
            first = false;
            // A range `a-z`, unless the `-` is last.
            if self.peek() == Some('-') && self.chars.get(self.pos + 1).is_some_and(|&n| n != ']') {
                self.pos += 1;
                let hi = match self.next() {
                    Some('\\') => match self.escape(true)? {
                        Matcher::Literal(l) => l,
                        _ => return err("a range in the pattern ends with a class such as \\d"),
                    },
                    Some('[') => {
                        return err("the pattern has a '[' inside a class: escape it as '\\['")
                    }
                    Some(h) => h,
                    None => return err("the pattern has a '[' without its ']'"),
                };
                if hi < single {
                    return err(format!(
                        "the range '{single}-{hi}' in the pattern is backwards"
                    ));
                }
                items.push(ClassItem::Range(single, hi));
            } else {
                items.push(ClassItem::Range(single, single));
            }
        }
        Ok(Matcher::Class { items, negated })
    }

    fn quantified(&mut self, atom: Node) -> Result<Node, PatternError> {
        let (min, max) = match self.peek() {
            Some('*') => (0, None),
            Some('+') => (1, None),
            Some('?') => (0, Some(1)),
            Some('{') => {
                self.pos += 1;
                let bounds = self.counts()?;
                self.pos -= 1; // the shared advance below
                bounds
            }
            _ => return Ok(atom),
        };
        self.pos += 1;
        if matches!(self.peek(), Some('*' | '+' | '?' | '{')) {
            return err(
                "the pattern repeats a repeat (lazy and possessive quantifiers such as '*?' are \
                 not supported)",
            );
        }
        if matches!(atom, Node::Empty) {
            return Ok(Node::Empty);
        }
        Ok(Node::Repeat {
            node: Box::new(atom),
            min,
            max,
        })
    }

    /// `n}`, `n,}` or `n,m}` after a `{`; leaves the position on the `}`'s next character.
    fn counts(&mut self) -> Result<(u32, Option<u32>), PatternError> {
        let bad = || {
            PatternError("the pattern has a '{' that is not a count such as {3} or {2,5}".into())
        };
        let min = self.number().ok_or_else(bad)?;
        let max = if self.eat(',') {
            if self.peek() == Some('}') {
                None
            } else {
                Some(self.number().ok_or_else(bad)?)
            }
        } else {
            Some(min)
        };
        if !self.eat('}') {
            return Err(bad());
        }
        if min > MAX_REPEAT || max.is_some_and(|m| m > MAX_REPEAT) {
            return err(format!(
                "the pattern repeats something more than {MAX_REPEAT} times"
            ));
        }
        if max.is_some_and(|m| m < min) {
            return err("the pattern has a count whose maximum is below its minimum");
        }
        Ok((min, max))
    }

    fn number(&mut self) -> Option<u32> {
        let start = self.pos;
        let mut n: u32 = 0;
        while let Some(d) = self.peek().and_then(|c| c.to_digit(10)) {
            n = n.saturating_mul(10).saturating_add(d);
            self.pos += 1;
        }
        (self.pos > start).then_some(n)
    }
}

// ---- the automaton ----------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Inst {
    Char(Matcher),
    /// Continue at both.
    Split(usize, usize),
    Jmp(usize),
    Match,
}

fn compile(node: &Node, prog: &mut Vec<Inst>) {
    match node {
        Node::Empty => {}
        Node::Char(m) => prog.push(Inst::Char(m.clone())),
        Node::Concat(nodes) => nodes.iter().for_each(|n| compile(n, prog)),
        Node::Alt(nodes) => {
            // split L1, next; L1: a; jmp end; next: split L2, next2; ... last
            let mut jumps = Vec::new();
            for (i, n) in nodes.iter().enumerate() {
                if i + 1 < nodes.len() {
                    let split = prog.len();
                    prog.push(Inst::Split(split + 1, 0));
                    compile(n, prog);
                    jumps.push(prog.len());
                    prog.push(Inst::Jmp(0));
                    let next = prog.len();
                    prog[split] = Inst::Split(split + 1, next);
                } else {
                    compile(n, prog);
                }
            }
            let end = prog.len();
            for j in jumps {
                prog[j] = Inst::Jmp(end);
            }
        }
        Node::Repeat { node, min, max } => {
            for _ in 0..*min {
                compile(node, prog);
            }
            match max {
                None => {
                    // L: split body, end; body; jmp L; end:
                    let split = prog.len();
                    prog.push(Inst::Split(split + 1, 0));
                    compile(node, prog);
                    prog.push(Inst::Jmp(split));
                    let end = prog.len();
                    prog[split] = Inst::Split(split + 1, end);
                }
                Some(max) => {
                    // Each optional copy: split body, end; body. All splits skip to the end.
                    let mut splits = Vec::new();
                    for _ in *min..*max {
                        splits.push(prog.len());
                        prog.push(Inst::Split(0, 0));
                        compile(node, prog);
                    }
                    let end = prog.len();
                    for s in splits {
                        prog[s] = Inst::Split(s + 1, end);
                    }
                }
            }
        }
    }
}

/// A set of program positions (sparse set with an insertion list).
struct States {
    list: Vec<usize>,
    member: Vec<bool>,
}

impl States {
    fn new(n: usize) -> States {
        States {
            list: Vec::with_capacity(n),
            member: vec![false; n],
        }
    }

    fn clear(&mut self) {
        for &pc in &self.list {
            self.member[pc] = false;
        }
        self.list.clear();
    }

    /// Add `pc` and every position reachable from it without reading a character.
    fn add(&mut self, prog: &[Inst], pc: usize, stack: &mut Vec<usize>) {
        stack.push(pc);
        while let Some(pc) = stack.pop() {
            if self.member[pc] {
                continue;
            }
            self.member[pc] = true;
            self.list.push(pc);
            match prog[pc] {
                Inst::Split(a, b) => {
                    stack.push(b);
                    stack.push(a);
                }
                Inst::Jmp(t) => stack.push(t),
                Inst::Char(_) | Inst::Match => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(p: &str, v: &str) -> bool {
        Pattern::new(p)
            .unwrap_or_else(|e| panic!("{p}: {e}"))
            .is_match(v)
    }

    #[test]
    fn whole_values_match() {
        for (p, yes, no) in [
            ("PO-\\d{4}-\\d{3}", "PO-2026-118", "PO-2026-1180"),
            ("^PO-\\d{4}-\\d{3}$", "PO-2026-118", "xPO-2026-118"),
            ("[A-Z]{2}\\d+", "AB12345", "ab12345"),
            ("[^0-9]+", "abc", "ab1"),
            ("(red|green|blue)", "green", "greenish"),
            ("(?:ab)+c?", "ababc", "abca"),
            ("a.c", "abc", "a\nc"),
            ("\\w+@\\w+", "a_1@b", "a-1@b"),
            ("x\\s?y", "x y", "x  y"),
            ("\\$\\d+", "$5", "5"),
            ("cost\\$", "cost$", "cost"),
            ("[a\\-z]", "-", "b"),
            ("[-a]", "-", "b"),
            ("[a-]", "-", "b"),
            ("[\\d\\s]+", "1 2", "1a"),
            ("[\\]]", "]", "["),
            ("a{2,}", "aaaa", "a"),
            ("a{0,2}", "", "aaa"),
            ("é+", "ééé", "e"),
            ("(a|)b", "b", "ab_"),
            ("(a*)*b", "aaab", "aaa"),
        ] {
            assert!(matches(p, yes), "{p} should match {yes:?}");
            assert!(!matches(p, no), "{p} should not match {no:?}");
        }
        assert!(matches("a*", ""));
        assert!(!matches("a+", ""));
    }

    #[test]
    fn unsafe_or_unclear_patterns_are_refused() {
        let too_long = "a".repeat(MAX_PATTERN_CHARS + 1);
        for p in [
            "",
            too_long.as_str(),
            "(a)\\1",
            "(?=a)a",
            "(?!a)b",
            "(?<=a)b",
            "(?<name>a)",
            "(?i)a",
            "a*?",
            "a++",
            "a{2}{3}",
            "*a",
            "a|*",
            "(a",
            "a)",
            "[a",
            "[]",
            "[z-a]",
            "[[:alpha:]]",
            "a{1001}",
            "a{3,2}",
            "a{x}",
            "a{2",
            "\\b",
            "\\p{L}",
            "\\",
            "a^b",
            "a$b",
            "}",
            "]",
            "a\u{0}",
            "((a{1000}){1000}){1000}",
            "(\\d{100}){100}",
        ] {
            assert!(Pattern::new(p).is_err(), "{p:?} should be refused");
        }
        // Just under the limits.
        let max_len = "a".repeat(MAX_PATTERN_CHARS);
        assert!(Pattern::new(&max_len).is_ok());
        assert!(Pattern::new("\\d{1000}").is_ok());
    }

    #[test]
    fn matching_is_linear_on_hostile_input() {
        // Catastrophic for a backtracking matcher; here a few thousand steps.
        let p = Pattern::new("(a|a)*(a*)*(a+)+b").unwrap();
        let value = "a".repeat(5000);
        let start = std::time::Instant::now();
        assert!(!p.is_match(&value));
        let mut ok = value.clone();
        ok.push('b');
        assert!(p.is_match(&ok));
        assert!(start.elapsed().as_secs() < 5, "{:?}", start.elapsed());
    }

    #[test]
    fn patterns_compare_by_source() {
        assert_eq!(Pattern::new("a+").unwrap(), Pattern::new("a+").unwrap());
        assert_ne!(Pattern::new("a+").unwrap(), Pattern::new("aa*").unwrap());
        assert_eq!(Pattern::new("^a$").unwrap().source(), "^a$");
    }
}
