//! Filter expression parser and evaluator for WebSocket event subscriptions.
//!
//! Supports a Wireshark-like filter syntax for `MessageRelayed` events:
//! ```text
//! msg_name == "GetBlockHeaders" && direction == "client_to_peer"
//! protocol == "eth" || protocol == "snap"
//! size > 1000 && tunnel_id starts_with "abc"
//! msg_name in ["Status", "GetBlockHeaders", "BlockHeaders"]
//! ```

use serde::Serialize;

use crate::events::{Direction, Protocol, ProxyEvent};

/// Maximum filter string length (4KB).
pub const MAX_FILTER_LENGTH: usize = 4096;

/// Maximum AST depth to prevent stack overflow.
pub const MAX_AST_DEPTH: usize = 16;

/// Maximum items in an IN list.
pub const MAX_IN_LIST_SIZE: usize = 100;

/// A parsed filter expression.
#[derive(Debug, Clone)]
pub enum FilterExpr {
    /// Always matches (empty filter).
    True,
    /// Single comparison: field op value.
    Comparison(Comparison),
    /// Logical AND of two expressions.
    And(Box<FilterExpr>, Box<FilterExpr>),
    /// Logical OR of two expressions.
    Or(Box<FilterExpr>, Box<FilterExpr>),
    /// Logical NOT of an expression.
    Not(Box<FilterExpr>),
}

/// A single comparison operation.
#[derive(Debug, Clone)]
pub struct Comparison {
    pub field: Field,
    pub op: ComparisonOp,
    pub value: FilterValue,
}

/// Filterable fields from MessageRelayed events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    TunnelId,
    Direction,
    MsgId,
    MsgName,
    Protocol,
    Size,
    Timestamp,
}

impl Field {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "tunnel_id" => Some(Field::TunnelId),
            "direction" => Some(Field::Direction),
            "msg_id" => Some(Field::MsgId),
            "msg_name" => Some(Field::MsgName),
            "protocol" => Some(Field::Protocol),
            "size" => Some(Field::Size),
            "timestamp" => Some(Field::Timestamp),
            _ => None,
        }
    }
}

/// Comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonOp {
    Eq,
    NotEq,
    Gt,
    Gte,
    Lt,
    Lte,
    Contains,
    StartsWith,
    In,
}

/// A value to compare against.
#[derive(Debug, Clone)]
pub enum FilterValue {
    String(String),
    Number(i64),
    StringList(Vec<String>),
}

/// Filter parse error with position information.
#[derive(Debug, Clone, Serialize)]
pub struct FilterParseError {
    pub message: String,
    pub position: usize,
}

impl std::fmt::Display for FilterParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at position {}", self.message, self.position)
    }
}

impl std::error::Error for FilterParseError {}

/// Context for evaluating filter expressions against a message.
/// Groups message attributes to avoid passing many individual parameters.
struct MessageContext<'a> {
    tunnel_id: &'a str,
    direction: Direction,
    msg_id: u8,
    msg_name: &'a str,
    protocol: Protocol,
    size: usize,
    timestamp: i64,
}

/// Client subscription state.
#[derive(Debug, Clone)]
pub struct Subscription {
    /// Compiled filter expression.
    pub filter: FilterExpr,
    /// Human-readable description of the filter.
    pub filter_description: String,
    /// When true, include raw message bytes in MessageRelayed events.
    pub include_raw: bool,
    /// Last event timestamp sent (for gap detection).
    pub last_event_ts: Option<i64>,
}

impl Default for Subscription {
    fn default() -> Self {
        Self {
            filter: FilterExpr::True,
            filter_description: "(all events)".to_string(),
            include_raw: false,
            last_event_ts: None,
        }
    }
}

impl FilterExpr {
    /// Parse a filter expression from a string.
    pub fn parse(input: &str) -> Result<Self, FilterParseError> {
        if input.len() > MAX_FILTER_LENGTH {
            return Err(FilterParseError {
                message: format!("Filter exceeds {} bytes", MAX_FILTER_LENGTH),
                position: 0,
            });
        }

        let mut parser = FilterParser::new(input);
        let expr = parser.parse_expr(0)?;

        // Ensure we consumed all input
        parser.skip_whitespace();
        if !parser.is_eof() {
            return Err(FilterParseError {
                message: format!("Unexpected token: '{}'", parser.peek_char().unwrap_or(' ')),
                position: parser.pos,
            });
        }

        Ok(expr)
    }

    /// Evaluate the filter against a MessageRelayed event.
    /// Returns true if the event matches the filter.
    pub fn matches(&self, event: &ProxyEvent) -> bool {
        // Only MessageRelayed events can be filtered
        let ProxyEvent::MessageRelayed {
            tunnel_id,
            direction,
            msg_id,
            msg_name,
            protocol,
            size,
            timestamp,
            ..
        } = event
        else {
            // Non-MessageRelayed events always match (they're lifecycle events)
            return true;
        };

        let ctx = MessageContext {
            tunnel_id,
            direction: *direction,
            msg_id: *msg_id,
            msg_name,
            protocol: *protocol,
            size: *size,
            timestamp: *timestamp,
        };

        self.eval(&ctx)
    }

    fn eval(&self, ctx: &MessageContext) -> bool {
        match self {
            FilterExpr::True => true,
            FilterExpr::Comparison(cmp) => cmp.eval(ctx),
            FilterExpr::And(a, b) => a.eval(ctx) && b.eval(ctx),
            FilterExpr::Or(a, b) => a.eval(ctx) || b.eval(ctx),
            FilterExpr::Not(inner) => !inner.eval(ctx),
        }
    }
}

impl Comparison {
    fn eval(&self, ctx: &MessageContext) -> bool {
        match self.field {
            Field::TunnelId => self.eval_string(ctx.tunnel_id),
            Field::Direction => self.eval_direction(ctx.direction),
            Field::MsgId => self.eval_number(ctx.msg_id as i64),
            Field::MsgName => self.eval_string(ctx.msg_name),
            Field::Protocol => self.eval_protocol(ctx.protocol),
            Field::Size => self.eval_number(ctx.size as i64),
            Field::Timestamp => self.eval_number(ctx.timestamp),
        }
    }

    fn eval_string(&self, actual: &str) -> bool {
        match (&self.op, &self.value) {
            (ComparisonOp::Eq, FilterValue::String(expected)) => actual == expected,
            (ComparisonOp::NotEq, FilterValue::String(expected)) => actual != expected,
            (ComparisonOp::Contains, FilterValue::String(expected)) => {
                actual.contains(expected.as_str())
            }
            (ComparisonOp::StartsWith, FilterValue::String(expected)) => {
                actual.starts_with(expected.as_str())
            }
            (ComparisonOp::In, FilterValue::StringList(list)) => list.iter().any(|s| s == actual),
            _ => false,
        }
    }

    fn eval_number(&self, actual: i64) -> bool {
        match (&self.op, &self.value) {
            (ComparisonOp::Eq, FilterValue::Number(expected)) => actual == *expected,
            (ComparisonOp::NotEq, FilterValue::Number(expected)) => actual != *expected,
            (ComparisonOp::Gt, FilterValue::Number(expected)) => actual > *expected,
            (ComparisonOp::Gte, FilterValue::Number(expected)) => actual >= *expected,
            (ComparisonOp::Lt, FilterValue::Number(expected)) => actual < *expected,
            (ComparisonOp::Lte, FilterValue::Number(expected)) => actual <= *expected,
            _ => false,
        }
    }

    fn eval_direction(&self, actual: Direction) -> bool {
        let actual_str = match actual {
            Direction::ClientToPeer => "client_to_peer",
            Direction::PeerToClient => "peer_to_client",
        };
        self.eval_string(actual_str)
    }

    fn eval_protocol(&self, actual: Protocol) -> bool {
        let actual_str = match actual {
            Protocol::P2p => "p2p",
            Protocol::Eth => "eth",
            Protocol::Snap => "snap",
            Protocol::Unknown => "unknown",
        };
        match (&self.op, &self.value) {
            (ComparisonOp::In, FilterValue::StringList(list)) => {
                list.iter().any(|s| s == actual_str)
            }
            _ => self.eval_string(actual_str),
        }
    }
}

/// Recursive descent parser for filter expressions.
struct FilterParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> FilterParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn parse_expr(&mut self, depth: usize) -> Result<FilterExpr, FilterParseError> {
        if depth > MAX_AST_DEPTH {
            return Err(FilterParseError {
                message: format!("Filter exceeds maximum depth of {}", MAX_AST_DEPTH),
                position: self.pos,
            });
        }

        self.skip_whitespace();
        if self.is_eof() {
            return Ok(FilterExpr::True);
        }

        self.parse_or_expr(depth)
    }

    /// or_expr = and_expr ("||" and_expr)*
    fn parse_or_expr(&mut self, depth: usize) -> Result<FilterExpr, FilterParseError> {
        let mut left = self.parse_and_expr(depth)?;

        loop {
            self.skip_whitespace();
            if self.consume_str("||") {
                let right = self.parse_and_expr(depth + 1)?;
                left = FilterExpr::Or(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }

        Ok(left)
    }

    /// and_expr = not_expr ("&&" not_expr)*
    fn parse_and_expr(&mut self, depth: usize) -> Result<FilterExpr, FilterParseError> {
        let mut left = self.parse_not_expr(depth)?;

        loop {
            self.skip_whitespace();
            if self.consume_str("&&") {
                let right = self.parse_not_expr(depth + 1)?;
                left = FilterExpr::And(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }

        Ok(left)
    }

    /// not_expr = "!" not_expr | primary
    fn parse_not_expr(&mut self, depth: usize) -> Result<FilterExpr, FilterParseError> {
        self.skip_whitespace();
        if self.consume_char('!') {
            let inner = self.parse_not_expr(depth + 1)?;
            Ok(FilterExpr::Not(Box::new(inner)))
        } else {
            self.parse_primary(depth)
        }
    }

    /// primary = "(" or_expr ")" | comparison
    fn parse_primary(&mut self, depth: usize) -> Result<FilterExpr, FilterParseError> {
        self.skip_whitespace();

        if self.consume_char('(') {
            let new_depth = depth + 1;
            if new_depth > MAX_AST_DEPTH {
                return Err(FilterParseError {
                    message: format!("Filter exceeds maximum depth of {}", MAX_AST_DEPTH),
                    position: self.pos,
                });
            }
            let expr = self.parse_or_expr(new_depth)?;
            self.skip_whitespace();
            if !self.consume_char(')') {
                return Err(FilterParseError {
                    message: "Expected ')'".to_string(),
                    position: self.pos,
                });
            }
            Ok(expr)
        } else {
            let cmp = self.parse_comparison()?;
            Ok(FilterExpr::Comparison(cmp))
        }
    }

    /// comparison = field op value
    fn parse_comparison(&mut self) -> Result<Comparison, FilterParseError> {
        self.skip_whitespace();

        // Parse field name
        let field_start = self.pos;
        let field_name = self.parse_identifier()?;
        let field = Field::from_str(&field_name).ok_or_else(|| FilterParseError {
            message: format!("Unknown field '{}'", field_name),
            position: field_start,
        })?;

        self.skip_whitespace();

        // Parse operator
        let op_start = self.pos;
        let op = self.parse_operator()?;

        self.skip_whitespace();

        // Parse value
        let value = self.parse_value(op, op_start)?;

        Ok(Comparison { field, op, value })
    }

    fn parse_identifier(&mut self) -> Result<String, FilterParseError> {
        let start = self.pos;
        while let Some(c) = self.peek_char() {
            if c.is_alphanumeric() || c == '_' {
                self.advance();
            } else {
                break;
            }
        }

        if self.pos == start {
            return Err(FilterParseError {
                message: "Expected identifier".to_string(),
                position: self.pos,
            });
        }

        Ok(self.input[start..self.pos].to_string())
    }

    fn parse_operator(&mut self) -> Result<ComparisonOp, FilterParseError> {
        let start = self.pos;

        // Try multi-character operators first
        if self.consume_str("==") {
            return Ok(ComparisonOp::Eq);
        }
        if self.consume_str("!=") {
            return Ok(ComparisonOp::NotEq);
        }
        if self.consume_str(">=") {
            return Ok(ComparisonOp::Gte);
        }
        if self.consume_str("<=") {
            return Ok(ComparisonOp::Lte);
        }
        if self.consume_char('>') {
            return Ok(ComparisonOp::Gt);
        }
        if self.consume_char('<') {
            return Ok(ComparisonOp::Lt);
        }

        // Try word operators
        if self.consume_word("contains") {
            return Ok(ComparisonOp::Contains);
        }
        if self.consume_word("starts_with") {
            return Ok(ComparisonOp::StartsWith);
        }
        if self.consume_word("in") {
            return Ok(ComparisonOp::In);
        }

        Err(FilterParseError {
            message: "Expected operator (==, !=, >, >=, <, <=, contains, starts_with, in)"
                .to_string(),
            position: start,
        })
    }

    fn parse_value(
        &mut self,
        op: ComparisonOp,
        op_start: usize,
    ) -> Result<FilterValue, FilterParseError> {
        self.skip_whitespace();

        match op {
            ComparisonOp::In => {
                // Parse list: ["a", "b", "c"]
                if !self.consume_char('[') {
                    return Err(FilterParseError {
                        message: "Expected '[' after 'in' operator".to_string(),
                        position: self.pos,
                    });
                }

                let mut list = Vec::new();
                loop {
                    self.skip_whitespace();
                    if self.consume_char(']') {
                        break;
                    }
                    if !list.is_empty() {
                        if !self.consume_char(',') {
                            return Err(FilterParseError {
                                message: "Expected ',' or ']' in list".to_string(),
                                position: self.pos,
                            });
                        }
                        self.skip_whitespace();
                    }

                    if list.len() >= MAX_IN_LIST_SIZE {
                        return Err(FilterParseError {
                            message: format!("IN list exceeds {} items", MAX_IN_LIST_SIZE),
                            position: op_start,
                        });
                    }

                    let s = self.parse_string_value()?;
                    list.push(s);
                }

                Ok(FilterValue::StringList(list))
            }
            ComparisonOp::Contains
            | ComparisonOp::StartsWith
            | ComparisonOp::Eq
            | ComparisonOp::NotEq => {
                // Could be string or number for Eq/NotEq
                if self.peek_char() == Some('"') {
                    Ok(FilterValue::String(self.parse_string_value()?))
                } else if matches!(op, ComparisonOp::Contains | ComparisonOp::StartsWith) {
                    // String operators require string value
                    Err(FilterParseError {
                        message: "Expected string value (use double quotes)".to_string(),
                        position: self.pos,
                    })
                } else {
                    // Try number
                    Ok(FilterValue::Number(self.parse_number_value()?))
                }
            }
            ComparisonOp::Gt | ComparisonOp::Gte | ComparisonOp::Lt | ComparisonOp::Lte => {
                // Numeric comparisons
                Ok(FilterValue::Number(self.parse_number_value()?))
            }
        }
    }

    fn parse_string_value(&mut self) -> Result<String, FilterParseError> {
        if !self.consume_char('"') {
            return Err(FilterParseError {
                message: "Expected '\"'".to_string(),
                position: self.pos,
            });
        }

        let start = self.pos;
        let mut result = String::new();

        loop {
            match self.peek_char() {
                None => {
                    return Err(FilterParseError {
                        message: "Unterminated string".to_string(),
                        position: start,
                    });
                }
                Some('"') => {
                    self.advance();
                    break;
                }
                Some('\\') => {
                    self.advance();
                    match self.peek_char() {
                        Some('"') => {
                            result.push('"');
                            self.advance();
                        }
                        Some('\\') => {
                            result.push('\\');
                            self.advance();
                        }
                        Some('n') => {
                            result.push('\n');
                            self.advance();
                        }
                        _ => {
                            return Err(FilterParseError {
                                message: "Invalid escape sequence".to_string(),
                                position: self.pos,
                            });
                        }
                    }
                }
                Some(c) => {
                    result.push(c);
                    self.advance();
                }
            }
        }

        Ok(result)
    }

    fn parse_number_value(&mut self) -> Result<i64, FilterParseError> {
        let start = self.pos;

        // Check for hex prefix
        if self.consume_str("0x") || self.consume_str("0X") {
            let hex_start = self.pos;
            while let Some(c) = self.peek_char() {
                if c.is_ascii_hexdigit() {
                    self.advance();
                } else {
                    break;
                }
            }

            if self.pos == hex_start {
                return Err(FilterParseError {
                    message: "Expected hex digits after 0x".to_string(),
                    position: hex_start,
                });
            }

            let hex_str = &self.input[hex_start..self.pos];
            return i64::from_str_radix(hex_str, 16).map_err(|_| FilterParseError {
                message: "Invalid hex number".to_string(),
                position: start,
            });
        }

        // Decimal number
        let negative = self.consume_char('-');
        let num_start = self.pos;

        while let Some(c) = self.peek_char() {
            if c.is_ascii_digit() {
                self.advance();
            } else {
                break;
            }
        }

        if self.pos == num_start {
            return Err(FilterParseError {
                message: "Expected number".to_string(),
                position: start,
            });
        }

        let num_str = &self.input[num_start..self.pos];
        let num: i64 = num_str.parse().map_err(|_| FilterParseError {
            message: "Invalid number".to_string(),
            position: start,
        })?;

        Ok(if negative { -num } else { num })
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek_char() {
            if c.is_whitespace() {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn advance(&mut self) {
        if let Some(c) = self.peek_char() {
            self.pos += c.len_utf8();
        }
    }

    fn consume_char(&mut self, expected: char) -> bool {
        if self.peek_char() == Some(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn consume_str(&mut self, expected: &str) -> bool {
        if self.input[self.pos..].starts_with(expected) {
            self.pos += expected.len();
            true
        } else {
            false
        }
    }

    fn consume_word(&mut self, expected: &str) -> bool {
        if self.input[self.pos..].starts_with(expected) {
            // Make sure it's a complete word (not a prefix of something else)
            let after = self.pos + expected.len();
            if after >= self.input.len() {
                self.pos = after;
                return true;
            }
            let next_char = self.input[after..].chars().next();
            if next_char.is_none_or(|c| !c.is_alphanumeric() && c != '_') {
                self.pos = after;
                return true;
            }
        }
        false
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.input.len()
    }
}

/// Generate a human-readable description of a filter expression.
impl FilterExpr {
    pub fn describe(&self) -> String {
        match self {
            FilterExpr::True => "(all events)".to_string(),
            FilterExpr::Comparison(cmp) => cmp.describe(),
            FilterExpr::And(a, b) => format!("({} && {})", a.describe(), b.describe()),
            FilterExpr::Or(a, b) => format!("({} || {})", a.describe(), b.describe()),
            FilterExpr::Not(inner) => format!("!{}", inner.describe()),
        }
    }
}

impl Comparison {
    fn describe(&self) -> String {
        let field_name = match self.field {
            Field::TunnelId => "tunnel_id",
            Field::Direction => "direction",
            Field::MsgId => "msg_id",
            Field::MsgName => "msg_name",
            Field::Protocol => "protocol",
            Field::Size => "size",
            Field::Timestamp => "timestamp",
        };

        let op_str = match self.op {
            ComparisonOp::Eq => "==",
            ComparisonOp::NotEq => "!=",
            ComparisonOp::Gt => ">",
            ComparisonOp::Gte => ">=",
            ComparisonOp::Lt => "<",
            ComparisonOp::Lte => "<=",
            ComparisonOp::Contains => "contains",
            ComparisonOp::StartsWith => "starts_with",
            ComparisonOp::In => "in",
        };

        let value_str = match &self.value {
            FilterValue::String(s) => format!("\"{}\"", s),
            FilterValue::Number(n) => n.to_string(),
            FilterValue::StringList(list) => {
                let items: Vec<String> = list.iter().map(|s| format!("\"{}\"", s)).collect();
                format!("[{}]", items.join(", "))
            }
        };

        format!("{} {} {}", field_name, op_str, value_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a test MessageRelayed event
    fn test_event(
        msg_name: &str,
        protocol: Protocol,
        size: usize,
        direction: Direction,
    ) -> ProxyEvent {
        ProxyEvent::MessageRelayed {
            tunnel_id: "abc123".to_string(),
            client_node_id: "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            direction,
            msg_id: 0x13,
            msg_name: msg_name.to_string(),
            protocol,
            size,
            decoded: None,
            raw: None,
            timestamp: 1704067200000,
        }
    }

    // ============ Parsing Tests ============

    #[test]
    fn parse_simple_equality() {
        let expr = FilterExpr::parse(r#"msg_name == "GetBlockHeaders""#).unwrap();
        assert!(matches!(expr, FilterExpr::Comparison(_)));
    }

    #[test]
    fn parse_numeric_comparison() {
        let expr = FilterExpr::parse("size > 1000").unwrap();
        assert!(matches!(expr, FilterExpr::Comparison(_)));
    }

    #[test]
    fn parse_hex_number() {
        let expr = FilterExpr::parse("msg_id == 0x13").unwrap();
        if let FilterExpr::Comparison(cmp) = expr {
            assert!(matches!(cmp.value, FilterValue::Number(19)));
        } else {
            panic!("Expected Comparison");
        }
    }

    #[test]
    fn parse_and_or_expressions() {
        let expr = FilterExpr::parse(r#"protocol == "eth" && size > 1000"#).unwrap();
        assert!(matches!(expr, FilterExpr::And(_, _)));

        let expr = FilterExpr::parse(r#"protocol == "eth" || protocol == "snap""#).unwrap();
        assert!(matches!(expr, FilterExpr::Or(_, _)));
    }

    #[test]
    fn parse_not_expression() {
        let expr = FilterExpr::parse(r#"!(msg_name == "Ping")"#).unwrap();
        assert!(matches!(expr, FilterExpr::Not(_)));
    }

    #[test]
    fn parse_grouped_parentheses() {
        let expr = FilterExpr::parse(r#"(protocol == "eth" || protocol == "snap") && size > 1000"#)
            .unwrap();
        assert!(matches!(expr, FilterExpr::And(_, _)));
    }

    #[test]
    fn parse_in_operator() {
        let expr = FilterExpr::parse(r#"msg_name in ["Status", "GetBlockHeaders"]"#).unwrap();
        if let FilterExpr::Comparison(cmp) = expr {
            assert!(matches!(cmp.op, ComparisonOp::In));
            if let FilterValue::StringList(list) = cmp.value {
                assert_eq!(list.len(), 2);
            } else {
                panic!("Expected StringList");
            }
        } else {
            panic!("Expected Comparison");
        }
    }

    #[test]
    fn parse_contains_starts_with() {
        let expr = FilterExpr::parse(r#"msg_name contains "Block""#).unwrap();
        assert!(matches!(expr, FilterExpr::Comparison(_)));

        let expr = FilterExpr::parse(r#"tunnel_id starts_with "abc""#).unwrap();
        assert!(matches!(expr, FilterExpr::Comparison(_)));
    }

    #[test]
    fn parse_error_unknown_field() {
        let err = FilterExpr::parse("foobar == 1").unwrap_err();
        assert!(err.message.contains("Unknown field"));
    }

    #[test]
    fn parse_error_invalid_syntax() {
        let err = FilterExpr::parse("size ??? 1000").unwrap_err();
        assert!(err.message.contains("Expected operator"));
    }

    #[test]
    fn parse_empty_returns_true() {
        let expr = FilterExpr::parse("").unwrap();
        assert!(matches!(expr, FilterExpr::True));

        let expr = FilterExpr::parse("   ").unwrap();
        assert!(matches!(expr, FilterExpr::True));
    }

    // ============ Evaluation Tests ============

    #[test]
    fn matches_protocol() {
        let expr = FilterExpr::parse(r#"protocol == "eth""#).unwrap();
        let event = test_event("Status", Protocol::Eth, 100, Direction::ClientToPeer);
        assert!(expr.matches(&event));

        let event = test_event("Status", Protocol::Snap, 100, Direction::ClientToPeer);
        assert!(!expr.matches(&event));
    }

    #[test]
    fn matches_msg_name() {
        let expr = FilterExpr::parse(r#"msg_name == "GetBlockHeaders""#).unwrap();
        let event = test_event(
            "GetBlockHeaders",
            Protocol::Eth,
            100,
            Direction::ClientToPeer,
        );
        assert!(expr.matches(&event));

        let event = test_event("BlockHeaders", Protocol::Eth, 100, Direction::ClientToPeer);
        assert!(!expr.matches(&event));
    }

    #[test]
    fn matches_size_comparison() {
        let expr = FilterExpr::parse("size > 1000").unwrap();
        let event = test_event("Status", Protocol::Eth, 1500, Direction::ClientToPeer);
        assert!(expr.matches(&event));

        let event = test_event("Status", Protocol::Eth, 500, Direction::ClientToPeer);
        assert!(!expr.matches(&event));
    }

    #[test]
    fn matches_direction() {
        let expr = FilterExpr::parse(r#"direction == "client_to_peer""#).unwrap();
        let event = test_event("Status", Protocol::Eth, 100, Direction::ClientToPeer);
        assert!(expr.matches(&event));

        let event = test_event("Status", Protocol::Eth, 100, Direction::PeerToClient);
        assert!(!expr.matches(&event));
    }

    #[test]
    fn matches_combined_and_or() {
        let expr = FilterExpr::parse(r#"protocol == "eth" && size > 1000"#).unwrap();
        let event = test_event("Status", Protocol::Eth, 1500, Direction::ClientToPeer);
        assert!(expr.matches(&event));

        let event = test_event("Status", Protocol::Eth, 500, Direction::ClientToPeer);
        assert!(!expr.matches(&event));

        let expr = FilterExpr::parse(r#"protocol == "eth" || protocol == "snap""#).unwrap();
        let event = test_event("Status", Protocol::Snap, 100, Direction::ClientToPeer);
        assert!(expr.matches(&event));
    }

    #[test]
    fn matches_tunnel_id_starts_with() {
        let expr = FilterExpr::parse(r#"tunnel_id starts_with "abc""#).unwrap();
        let event = test_event("Status", Protocol::Eth, 100, Direction::ClientToPeer);
        assert!(expr.matches(&event)); // tunnel_id is "abc123"

        let expr = FilterExpr::parse(r#"tunnel_id starts_with "xyz""#).unwrap();
        assert!(!expr.matches(&event));
    }

    #[test]
    fn matches_tunnel_id_contains() {
        let expr = FilterExpr::parse(r#"tunnel_id contains "c12""#).unwrap();
        let event = test_event("Status", Protocol::Eth, 100, Direction::ClientToPeer);
        assert!(expr.matches(&event)); // tunnel_id is "abc123"

        let expr = FilterExpr::parse(r#"tunnel_id contains "xyz""#).unwrap();
        assert!(!expr.matches(&event));
    }

    #[test]
    fn matches_in_list() {
        let expr = FilterExpr::parse(r#"msg_name in ["Status", "GetBlockHeaders"]"#).unwrap();
        let event = test_event("Status", Protocol::Eth, 100, Direction::ClientToPeer);
        assert!(expr.matches(&event));

        let event = test_event("BlockHeaders", Protocol::Eth, 100, Direction::ClientToPeer);
        assert!(!expr.matches(&event));
    }

    #[test]
    fn matches_protocol_in_list() {
        let expr = FilterExpr::parse(r#"protocol in ["eth", "snap"]"#).unwrap();
        let event = test_event("Status", Protocol::Eth, 100, Direction::ClientToPeer);
        assert!(expr.matches(&event));

        let event = test_event("Status", Protocol::P2p, 100, Direction::ClientToPeer);
        assert!(!expr.matches(&event));
    }

    // ============ Security Limits Tests ============

    #[test]
    fn reject_filter_too_long() {
        let long_filter = "a".repeat(MAX_FILTER_LENGTH + 1);
        let err = FilterExpr::parse(&long_filter).unwrap_err();
        assert!(err.message.contains("exceeds"));
    }

    #[test]
    fn reject_ast_too_deep() {
        // Create deeply nested expression with parentheses: (((((msg_id == 1)))))...
        let mut filter = r#"msg_id == 1"#.to_string();
        for _ in 0..MAX_AST_DEPTH + 5 {
            filter = format!("({})", filter);
        }
        let err = FilterExpr::parse(&filter).unwrap_err();
        assert!(err.message.contains("depth"));
    }

    #[test]
    fn reject_in_list_too_large() {
        let items: Vec<String> = (0..MAX_IN_LIST_SIZE + 1)
            .map(|i| format!("\"item{}\"", i))
            .collect();
        let filter = format!("msg_name in [{}]", items.join(", "));
        let err = FilterExpr::parse(&filter).unwrap_err();
        assert!(err.message.contains("exceeds"));
    }

    // ============ Lifecycle Events Tests ============

    #[test]
    fn lifecycle_events_always_match() {
        let expr = FilterExpr::parse(r#"protocol == "eth""#).unwrap();

        // PeerConnected should always match (it's a lifecycle event)
        let event = ProxyEvent::PeerConnected {
            tunnel_id: "test".to_string(),
            client_node_id: "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            client_id: "besu".to_string(),
            remote_enode: "enode://abc".to_string(),
            network_id: 1,
            fork_hash: "fc64ec04".to_string(),
            fork_next: 0,
            capabilities: vec![],
            timestamp: 0,
        };
        assert!(expr.matches(&event));

        // PeerDisconnected should always match
        let event = ProxyEvent::PeerDisconnected {
            tunnel_id: "test".to_string(),
            client_node_id: "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            reason: "client quit".to_string(),
            timestamp: 0,
        };
        assert!(expr.matches(&event));
    }

    // ============ Description Tests ============

    #[test]
    fn describe_filter() {
        let expr = FilterExpr::parse(r#"protocol == "eth" && size > 1000"#).unwrap();
        let desc = expr.describe();
        assert!(desc.contains("protocol"));
        assert!(desc.contains("eth"));
        assert!(desc.contains("size"));
        assert!(desc.contains("1000"));
    }
}
