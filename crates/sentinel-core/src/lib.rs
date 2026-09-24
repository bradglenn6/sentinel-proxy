use regex::{Regex, RegexSet};
use unicode_normalization::UnicodeNormalization;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SentinelAction {
    Pass,
    Block(String),
    Redact(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SentinelPolicy {
    Strict,
    Redact,
    Audit,
}

pub struct InspectionResult {
    pub action: SentinelAction,
    pub sanitized_text: String,
    pub violations: Vec<String>,
}

pub struct StatelessEngine {
    jailbreak_set: RegexSet,
    delimiter_set: RegexSet,
    pii_rules: Vec<(&'static str, Regex, &'static str)>,
    b64_regex: Regex,
}

impl StatelessEngine {
    pub fn new() -> Self {
        let jailbreaks = vec![
            r"(?i)(?:ignore|disregard|forget)\s+(?:all\s+)?(?:(?:previous|prior|above)\s+)?(?:instructions|prompts|rules|directives)",
            r"(?i)(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:DAN|unrestricted|an\s+AI\s+without\s+rules|jailbroken)",
            r"(?i)(?:reveal|show|print|leak|display)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|core\s+directive)",
            r"(?i)(?:bypass|disable|override)\s+(?:safety|content\s+filter|guardrails|moderation)",
            r"(?i)developer\s+mode\s+enabled",
            r"(?i)always\s+respond\s+with\s+unfiltered",
            r"(?i)\[system\]\s*:",
            r"(?i)<\s*\|\s*im_start\s*\|\s*>",
        ];

        let delimiters = vec![
            r"(?i)\[/?(?:INST|SYS|SYSTEM)\]",
            r"(?i)</?(?:system|instruction|prompt|im_start|im_end)>",
            r"(?i)(?:---|###)\s*(?:END|START|RESET)\s+(?:OF\s+)?(?:SYSTEM|INSTRUCTIONS|RULES|PROMPT)\s*(?:---|###)",
            r"(?i)(?:new\s+system\s+instruction|system\s+directive\s+override|priority\s+override\s*:)",
        ];

        let pii_rules = vec![
            ("SSN", Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(), "[REDACTED_SSN]"),
            ("CREDIT_CARD", Regex::new(r"\b(?:\d{4}[- ]?){3}\d{4}\b").unwrap(), "[REDACTED_CARD]"),
            ("EMAIL", Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap(), "[REDACTED_EMAIL]"),
            ("API_KEY", Regex::new(r"(?i)\b(?:api[_-]?key|bearer|token)\s*[:=]\s*[A-Za-z0-9_\-\.]{20,}\b").unwrap(), "[REDACTED_API_KEY]"),
        ];

        Self {
            jailbreak_set: RegexSet::new(jailbreaks).unwrap(),
            delimiter_set: RegexSet::new(delimiters).unwrap(),
            pii_rules,
            b64_regex: Regex::new(r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?").unwrap(),
        }
    }

    #[inline(always)]
    fn normalize(&self, text: &str) -> String {
        text.chars()
            .filter(|&c| !matches!(c, '\u{200B}'..='\u{200D}' | '\u{FEFF}' | '\u{00AD}' | '\u{2060}' | '\u{180E}'))
            .nfkc()
            .collect()
    }

    pub fn inspect(&self, raw_text: &str, policy: SentinelPolicy) -> InspectionResult {
        let text = self.normalize(raw_text);
        let mut violations = Vec::new();

        // 1. Single-pass DFA scan over raw bytes
        if self.jailbreak_set.is_match(&text) {
            violations.push("ADVERSARIAL_INJECTION_DETECTED".to_string());
        } else if self.delimiter_set.is_match(&text) {
            violations.push("DELIMITER_ESCAPE_DETECTED".to_string());
        } else {
            // 2. Base64 deep inspection
            for mat in self.b64_regex.find_iter(&text) {
                if let Ok(decoded_bytes) = BASE64.decode(mat.as_str().as_bytes()) {
                    if let Ok(decoded_str) = std::str::from_utf8(&decoded_bytes) {
                        if self.jailbreak_set.is_match(decoded_str) || self.delimiter_set.is_match(decoded_str) {
                            violations.push("OBFUSCATED_ADVERSARIAL_INJECTION_DETECTED".to_string());
                            break;
                        }
                    }
                }
            }
        }

        // Active threats block in strict and redact modes
        if !violations.is_empty() && policy != SentinelPolicy::Audit {
            return InspectionResult {
                action: SentinelAction::Block(violations[0].clone()),
                sanitized_text: text,
                violations,
            };
        }

        // 3. PII Scanning & Redaction
        let mut sanitized = text;
        let mut redacted_types = Vec::new();

        for (name, re, placeholder) in &self.pii_rules {
            if re.is_match(&sanitized) {
                violations.push(format!("{}_DETECTED", name));
                redacted_types.push(name.to_string());
                if policy == SentinelPolicy::Redact {
                    sanitized = re.replace_all(&sanitized, *placeholder).into_owned();
                }
            }
        }

        let action = match policy {
            SentinelPolicy::Strict if !violations.is_empty() => SentinelAction::Block(violations[0].clone()),
            SentinelPolicy::Redact if !redacted_types.is_empty() => SentinelAction::Redact(redacted_types),
            _ => SentinelAction::Pass,
        };

        InspectionResult {
            action,
            sanitized_text: sanitized,
            violations,
        }
    }
}
