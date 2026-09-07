//! Grammar compilation (Plan Task 19): the validated v1 schema subset
//! compiles to a bounded GBNF grammar handed to llama.cpp BEFORE
//! generation starts. Compilation failure is a typed reject with zero
//! effect — no unconstrained fallback grammar exists.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grammar {
    /// Deterministic GBNF source text.
    pub source: String,
    /// sha256 of the compiled source (diagnostics only).
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrammarError {
    /// Any schema the compiler cannot express — the attempt fails
    /// typed; the worker NEVER falls back to unconstrained output.
    CompilationFailed,
}

/// Compiles the schema subset to GBNF. Input must already have passed
/// `validate_schema_subset`; the compiler is defensive anyway.
pub fn compile(schema: &Value) -> Result<Grammar, GrammarError> {
    let mut g = GrammarCompiler { out: String::new() };
    let root = g.rule(schema, 0)?;
    g.out
        .insert_str(0, &format!("space ::= [ \\t]*\nroot ::= {root}\n"));
    let digest = {
        use sha2::Digest as _;
        let mut h = sha2::Sha256::new();
        sha2::Digest::update(&mut h, g.out.as_bytes());
        format!("sha256:{}", hex(&sha2::Digest::finalize(h)))
    };
    Ok(Grammar {
        source: g.out,
        digest,
    })
}

struct GrammarCompiler {
    out: String,
}

const MAX_RULE_DEPTH: usize = 16;

impl GrammarCompiler {
    /// Emits a rule named `name-N` for a node; returns the reference.
    fn rule(&mut self, schema: &Value, depth: usize) -> Result<String, GrammarError> {
        if depth > MAX_RULE_DEPTH {
            return Err(GrammarError::CompilationFailed);
        }
        let name = format!("d{depth}-{}", self.out.len());
        let body = self.body(schema, depth)?;
        self.out.push_str(&format!("{name} ::= {body}\n"));
        Ok(name)
    }

    fn body(&mut self, schema: &Value, depth: usize) -> Result<String, GrammarError> {
        let Value::Object(m) = schema else {
            return Err(GrammarError::CompilationFailed);
        };
        if let Some(Value::Array(values)) = m.get("enum") {
            let alts: Vec<String> = values
                .iter()
                .map(quote_json_literal)
                .collect::<Result<_, _>>()?;
            return Ok(alts.join(" | "));
        }
        let ty = match m.get("type") {
            Some(Value::String(t)) => t.as_str(),
            _ => return Err(GrammarError::CompilationFailed),
        };
        Ok(match ty {
            "string" => String::from("\"\\\"\" [^\"\\\\]* \"\\\"\""),
            "integer" => "[0-9]+".into(),
            "number" => "[0-9]+ (\".\" [0-9]+)?".into(),
            "boolean" => "\"true\" | \"false\"".into(),
            "null" => "\"null\"".into(),
            "array" => {
                let Some(items) = m.get("items") else {
                    return Err(GrammarError::CompilationFailed);
                };
                let item_ref = self.rule(items, depth + 1)?;
                format!("\"[\" space ({item_ref} (\",\" space {item_ref})*)? \"]\"")
            }
            "object" => self.object_body(schema, depth)?,
            _ => return Err(GrammarError::CompilationFailed),
        })
    }

    fn object_body(&mut self, m: &Value, depth: usize) -> Result<String, GrammarError> {
        let Value::Object(props) = m.get("properties").ok_or(GrammarError::CompilationFailed)?
        else {
            return Err(GrammarError::CompilationFailed);
        };
        let required: Vec<String> = match m.get("required") {
            Some(Value::Array(items)) => items
                .iter()
                .map(|i| match i {
                    Value::String(s) => Ok(s.clone()),
                    _ => Err(GrammarError::CompilationFailed),
                })
                .collect::<Result<_, _>>()?,
            None => Vec::new(),
            _ => return Err(GrammarError::CompilationFailed),
        };
        // Closed objects only: required properties in declared order;
        // optional properties are OUT of the compiled subset.
        if required.len() != props.len() {
            return Err(GrammarError::CompilationFailed);
        }
        let mut parts = Vec::new();
        for key in &required {
            let sub = props.get(key).ok_or(GrammarError::CompilationFailed)?;
            let sub_ref = self.rule(sub, depth + 1)?;
            parts.push(format!(
                "\"\\\"{}\\\"\" space \":\" space {sub_ref}",
                escape(key)
            ));
        }
        if parts.is_empty() {
            return Ok("\"{\" space \"}\"".into());
        }
        let joined = parts.join(" \",\" space ");
        Ok(format!("\"{{\" space {joined} space \"}}\""))
    }
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn quote_json_literal(v: &Value) -> Result<String, GrammarError> {
    serde_json::to_string(v).map_err(|_| GrammarError::CompilationFailed)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
