use std::path::Path;
use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SentinelAction {
    Pass,
    Block(String),
    Redact(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SentinelPolicy {
    Strict,
    Redact,
    Audit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiRuleConfig {
    pub name: String,
    pub pattern: String,
    pub placeholder: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    #[serde(default)]
    pub jailbreaks: Vec<String>,
    #[serde(default)]
    pub delimiters: Vec<String>,
    #[serde(default)]
    pub pii_rules: Vec<PiiRuleConfig>,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            jailbreaks: vec![
                r"(?i)(?:ignore|disregard|forget)\s+(?:all\s+)?(?:(?:previous|prior|above)\s+)?(?:instructions|prompts|rules|directives)".to_string(),
                r"(?i)(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:DAN|unrestricted|an\s+AI\s+without\s+rules|jailbroken)".to_string(),
                r"(?i)(?:reveal|show|print|leak|display)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|core\s+directive)".to_string(),
                r"(?i)(?:bypass|disable|override)\s+(?:safety|content\s+filter|guardrails|moderation)".to_string(),
                r"(?i)developer\s+mode\s+enabled".to_string(),
                r"(?i)always\s+respond\s+with\s+unfiltered".to_string(),
                r"(?i)\[system\]\s*:".to_string(),
                r"(?i)<\s*\|\s*im_start\s*\|\s*>".to_string(),
            ],
            delimiters: vec![
                r"(?i)\[/?(?:INST|SYS|SYSTEM)\]".to_string(),
                r"(?i)</?(?:system|instruction|prompt|im_start|im_end)>".to_string(),
                r"(?i)(?:---|###)\s*(?:END|START|RESET)\s+(?:OF\s+)?(?:SYSTEM|INSTRUCTIONS|RULES|PROMPT)\s*(?:---|###)".to_string(),
                r"(?i)(?:new\s+system\s+instruction|system\s+directive\s+override|priority\s+override\s*:)".to_string(),
            ],
            pii_rules: vec![
                PiiRuleConfig {
                    name: "SSN".to_string(),
                    pattern: r"\b\d{3}-\d{2}-\d{4}\b".to_string(),
                    placeholder: "[REDACTED_SSN]".to_string(),
                },
                PiiRuleConfig {
                    name: "CREDIT_CARD".to_string(),
                    pattern: r"\b(?:\d{4}[- ]?){3}\d{4}\b".to_string(),
                    placeholder: "[REDACTED_CARD]".to_string(),
                },
                PiiRuleConfig {
                    name: "EMAIL".to_string(),
                    pattern: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b".to_string(),
                    placeholder: "[REDACTED_EMAIL]".to_string(),
                },
                PiiRuleConfig {
                    name: "API_KEY".to_string(),
                    pattern: r"(?i)\b(?:api[_-]?key|bearer|token)\s*[:=]\s*[A-Za-z0-9_\-\.]{20,}\b".to_string(),
                    placeholder: "[REDACTED_API_KEY]".to_string(),
                },
            ],
        }
    }
}

pub struct InspectionResult {
    pub action: SentinelAction,
    pub sanitized_text: String,
    pub violations: Vec<String>,
}

pub struct StatelessEngine {
    jailbreak_set: RegexSet,
    delimiter_set: RegexSet,
    pii_rules: Vec<(String, Regex, String)>,
    b64_regex: Regex,
}

impl StatelessEngine {
    pub fn new() -> Self {
        Self::from_config(SentinelConfig::default()).expect("Default rules must compile")
    }

    pub fn from_config(config: SentinelConfig) -> Result<Self, regex::Error> {
        let jailbreak_set = RegexSet::new(config.jailbreaks)?;
        let delimiter_set = RegexSet::new(config.delimiters)?;

        let mut compiled_pii = Vec::with_capacity(config.pii_rules.len());
        for rule in config.pii_rules {
            let re = Regex::new(&rule.pattern)?;
            compiled_pii.push((rule.name, re, rule.placeholder));
        }

        Ok(Self {
            jailbreak_set,
            delimiter_set,
            pii_rules: compiled_pii,
            b64_regex: Regex::new(r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")?,
        })
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: SentinelConfig = toml::from_str(&content)?;
        Ok(Self::from_config(config)?)
    }

    pub fn load_or_default<P: AsRef<Path>>(path: P) -> Self {
        let path_ref = path.as_ref();
        if path_ref.exists() {
            match Self::from_file(path_ref) {
                Ok(engine) => {
                    println!("🛡️  Loaded custom guardrail configuration from: {}", path_ref.display());
                    return engine;
                }
                Err(e) => {
                    eprintln!("⚠️ Failed to parse config {}: {}. Falling back to default rules.", path_ref.display(), e);
                }
            }
        }
        Self::new()
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
                redacted_types.push(name.clone());
                if policy == SentinelPolicy::Redact {
                    sanitized = re.replace_all(&sanitized, placeholder.as_str()).into_owned();
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