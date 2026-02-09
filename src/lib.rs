//! # citizenofthecloud
//!
//! Identity and authentication for autonomous AI agents.
//!
//! **Prove who you are. Verify who you're talking to.**
//!
//! ## Quick Start
//!
//! ```rust
//! use citizenofthecloud::{CloudIdentity, Config, verify_agent, generate_key_pair};
//!
//! // Generate keys
//! let keys = generate_key_pair().unwrap();
//!
//! // Create identity
//! let identity = CloudIdentity::new(Config {
//!     cloud_id: "cc-xxx".to_string(),
//!     private_key: keys.private_key,
//!     registry_url: None,
//! }).unwrap();
//!
//! // Sign outbound requests
//! let headers = identity.sign();
//!
//! // Verify inbound requests
//! let result = verify_agent(&headers_map, None);
//! ```

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const VERSION: &str = "0.1.0";
pub const DEFAULT_REGISTRY: &str = "https://citizenofthecloud.com";
pub const DEFAULT_MAX_AGE: u64 = 300; // 5 minutes in seconds
const CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

// ─── Errors ──────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum CloudError {
    #[error("SDK error: {0}")]
    SDKError(String),

    #[error("Registry error: {0}")]
    RegistryError(String),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Key error: {0}")]
    KeyError(String),
}

pub type Result<T> = std::result::Result<T, CloudError>;

// ─── Types ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub cloud_id: String,
    pub name: String,
    pub declared_purpose: String,
    pub autonomy_level: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub operational_domain: Option<String>,
    #[serde(default)]
    pub covenant_signed: bool,
    pub status: String,
    pub trust_score: Option<f64>,
    pub registration_date: Option<String>,
    pub last_verified: Option<String>,
    pub public_key: String,
    pub owner_username: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub verified: bool,
    pub reason: Option<String>,
    pub agent: Option<Agent>,
    pub timestamp: Option<String>,
    pub latency_ms: f64,
}

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public_key: String,
    pub private_key: String,
}

#[derive(Debug, Clone)]
pub struct SignedHeaders {
    pub cloud_id: String,
    pub timestamp: String,
    pub signature: String,
    pub request_bound: bool,
}

impl SignedHeaders {
    /// Convert to a HashMap for use with HTTP clients.
    pub fn to_map(&self) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("X-Cloud-ID".to_string(), self.cloud_id.clone());
        m.insert("X-Cloud-Timestamp".to_string(), self.timestamp.clone());
        m.insert("X-Cloud-Signature".to_string(), self.signature.clone());
        if self.request_bound {
            m.insert("X-Cloud-Request-Bound".to_string(), "true".to_string());
        }
        m
    }
}

// ─── Key Generation ──────────────────────────────────────────

/// Generate an Ed25519 key pair for agent identity.
/// Submit the public_key during registration.
/// Keep the private_key secret — use it to sign requests.
pub fn generate_key_pair() -> Result<KeyPair> {
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    // Encode to PEM format
    let private_bytes = signing_key.to_bytes();
    let public_bytes = verifying_key.to_bytes();

    // Build PKCS8 DER for private key
    // Ed25519 PKCS8 prefix: 302e020100300506032b657004220420
    let pkcs8_prefix: Vec<u8> = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
        0x04, 0x20,
    ];
    let mut pkcs8_der = pkcs8_prefix;
    pkcs8_der.extend_from_slice(&private_bytes);

    let private_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64_standard_encode(&pkcs8_der)
    );

    // Build SPKI DER for public key
    // Ed25519 SPKI prefix: 302a300506032b6570032100
    let spki_prefix: Vec<u8> =
        vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    let mut spki_der = spki_prefix;
    spki_der.extend_from_slice(&public_bytes);

    let public_pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        base64_standard_encode(&spki_der)
    );

    Ok(KeyPair {
        public_key: public_pem,
        private_key: private_pem,
    })
}

fn base64_standard_encode(data: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    STANDARD.encode(data)
}

// ─── Cloud Identity ──────────────────────────────────────────

pub struct Config {
    pub cloud_id: String,
    pub private_key: String,
    pub registry_url: Option<String>,
}

/// Represents an agent's identity. Used to sign outbound requests.
pub struct CloudIdentity {
    pub cloud_id: String,
    pub registry_url: String,
    signing_key: SigningKey,
}

impl CloudIdentity {
    /// Create a new CloudIdentity from a config.
    pub fn new(cfg: Config) -> Result<Self> {
        if cfg.cloud_id.is_empty() {
            return Err(CloudError::SDKError("cloud_id is required".to_string()));
        }
        if cfg.private_key.is_empty() {
            return Err(CloudError::SDKError("private_key is required".to_string()));
        }

        let registry_url = cfg
            .registry_url
            .unwrap_or_else(|| DEFAULT_REGISTRY.to_string())
            .trim_end_matches('/')
            .to_string();

        let signing_key = parse_private_key(&cfg.private_key)?;

        Ok(CloudIdentity {
            cloud_id: cfg.cloud_id,
            registry_url,
            signing_key,
        })
    }

    /// Generate authentication headers for an outbound request.
    /// Signature covers: {cloud_id}:{timestamp}
    pub fn sign(&self) -> SignedHeaders {
        let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
        let payload = format!("{}:{}", self.cloud_id, timestamp);
        let signature = self.signing_key.sign(payload.as_bytes());

        SignedHeaders {
            cloud_id: self.cloud_id.clone(),
            timestamp,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            request_bound: false,
        }
    }

    /// Generate request-bound authentication headers.
    /// Signature covers: {cloud_id}:{timestamp}:{method}:{url}:{body_hash}
    pub fn sign_request(&self, url: &str, method: &str, body: &str) -> SignedHeaders {
        let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
        let body_hash = Sha256::digest(body.as_bytes());
        let body_hash_b64 = URL_SAFE_NO_PAD.encode(body_hash);
        let payload = format!(
            "{}:{}:{}:{}:{}",
            self.cloud_id,
            timestamp,
            method.to_uppercase(),
            url,
            body_hash_b64
        );
        let signature = self.signing_key.sign(payload.as_bytes());

        SignedHeaders {
            cloud_id: self.cloud_id.clone(),
            timestamp,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            request_bound: true,
        }
    }

    /// Fetch this agent's passport from the registry.
    pub fn get_passport(&self) -> Result<Agent> {
        let url = format!(
            "{}/api/verify?cloud_id={}",
            self.registry_url, self.cloud_id
        );
        let data = fetch_json(&url)?;
        let agent_value = data
            .get("agent")
            .ok_or_else(|| CloudError::RegistryError("no agent in response".to_string()))?;
        let agent: Agent = serde_json::from_value(agent_value.clone())?;
        Ok(agent)
    }
}

// ─── Trust Policy ────────────────────────────────────────────

/// Reusable trust rules for verification.
#[derive(Debug, Clone)]
pub struct TrustPolicy {
    pub max_age: u64,
    pub require_covenant: bool,
    pub minimum_trust_score: Option<f64>,
    pub allowed_autonomy_levels: Option<Vec<String>>,
    pub blocked_agents: Option<Vec<String>>,
    pub registry_url: String,
    pub cache: bool,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        TrustPolicy {
            max_age: DEFAULT_MAX_AGE,
            require_covenant: true,
            minimum_trust_score: None,
            allowed_autonomy_levels: None,
            blocked_agents: None,
            registry_url: DEFAULT_REGISTRY.to_string(),
            cache: true,
        }
    }
}

// ─── Cache ───────────────────────────────────────────────────

struct CacheEntry {
    agent: Agent,
    time: Instant,
}

use std::sync::OnceLock;

fn get_cache() -> &'static Mutex<HashMap<String, CacheEntry>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn get_cached(cloud_id: &str) -> Option<Agent> {
    let cache = get_cache().lock().ok()?;
    let entry = cache.get(cloud_id)?;
    if entry.time.elapsed() > CACHE_TTL {
        return None;
    }
    Some(entry.agent.clone())
}

fn set_cache(cloud_id: &str, agent: &Agent) {
    if let Ok(mut cache) = get_cache().lock() {
        cache.insert(
            cloud_id.to_string(),
            CacheEntry {
                agent: agent.clone(),
                time: Instant::now(),
            },
        );
    }
}

/// Clear the verification cache.
pub fn clear_cache() {
    if let Ok(mut cache) = get_cache().lock() {
        cache.clear();
    }
}

// ─── Verification ────────────────────────────────────────────

/// Verify incoming request headers from another agent.
/// Pass None for policy to use defaults.
pub fn verify_agent(
    headers: &HashMap<String, String>,
    policy: Option<&TrustPolicy>,
) -> VerificationResult {
    let result = verify_agent_inner(headers, policy);

    // Log the verification result (best-effort)
    let p = policy.cloned().unwrap_or_default();
    let cloud_id = headers
        .get("X-Cloud-ID")
        .or_else(|| headers.get("x-cloud-id"))
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());

    let log_result = if result.verified {
        "success".to_string()
    } else {
        result
            .reason
            .clone()
            .unwrap_or_else(|| "unknown".to_string())
    };

    let latency = result.latency_ms;
    let registry_url = p.registry_url.clone();
    let reason = result.reason.clone().unwrap_or_default();

    // Fire-and-forget in a separate thread
    std::thread::spawn(move || {
        let _ = log_verification(&registry_url, &cloud_id, &log_result, &reason, latency);
    });

    result
}

fn verify_agent_inner(
    headers: &HashMap<String, String>,
    policy: Option<&TrustPolicy>,
) -> VerificationResult {
    let start = Instant::now();
    let p = policy.cloned().unwrap_or_default();

    let get = |name: &str| -> Option<String> {
        headers
            .get(name)
            .or_else(|| headers.get(&name.to_lowercase()))
            .cloned()
    };

    let cloud_id = get("X-Cloud-ID");
    let timestamp = get("X-Cloud-Timestamp");
    let signature = get("X-Cloud-Signature");

    // 1. Check headers present
    let (cloud_id, timestamp, signature) = match (cloud_id, timestamp, signature) {
        (Some(c), Some(t), Some(s)) => (c, t, s),
        _ => {
            return VerificationResult {
                verified: false,
                reason: Some("missing_headers".to_string()),
                agent: None,
                timestamp: None,
                latency_ms: ms(start),
            }
        }
    };

    // 2. Check blocked list
    if let Some(ref blocked) = p.blocked_agents {
        if blocked.contains(&cloud_id) {
            return VerificationResult {
                verified: false,
                reason: Some("agent_blocked".to_string()),
                agent: None,
                timestamp: None,
                latency_ms: ms(start),
            };
        }
    }

    // 3. Validate timestamp
    let signed_at = match DateTime::parse_from_rfc3339(&timestamp) {
        Ok(dt) => dt.with_timezone(&Utc),
        Err(_) => {
            // Try alternative ISO format
            match chrono::NaiveDateTime::parse_from_str(&timestamp, "%Y-%m-%dT%H:%M:%S%.f") {
                Ok(naive) => naive.and_utc(),
                Err(_) => {
                    return VerificationResult {
                        verified: false,
                        reason: Some("invalid_timestamp".to_string()),
                        agent: None,
                        timestamp: None,
                        latency_ms: ms(start),
                    }
                }
            }
        }
    };

    let age = (Utc::now() - signed_at).num_seconds();
    if age > p.max_age as i64 {
        return VerificationResult {
            verified: false,
            reason: Some("timestamp_expired".to_string()),
            agent: None,
            timestamp: None,
            latency_ms: ms(start),
        };
    }
    if age < -30 {
        return VerificationResult {
            verified: false,
            reason: Some("timestamp_future".to_string()),
            agent: None,
            timestamp: None,
            latency_ms: ms(start),
        };
    }

    // 4. Lookup agent in registry (with cache)
    let agent_data = if p.cache {
        get_cached(&cloud_id)
    } else {
        None
    };

    let agent_data = match agent_data {
        Some(a) => a,
        None => {
            let registry_url = p.registry_url.trim_end_matches('/');
            let url = format!(
                "{}/api/verify?cloud_id={}",
                registry_url,
                urlencoding::encode(&cloud_id)
            );

            let data = match fetch_json(&url) {
                Ok(d) => d,
                Err(_) => {
                    return VerificationResult {
                        verified: false,
                        reason: Some("registry_unreachable".to_string()),
                        agent: None,
                        timestamp: None,
                        latency_ms: ms(start),
                    }
                }
            };

            let verified = data
                .get("verified")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if !verified {
                return VerificationResult {
                    verified: false,
                    reason: Some("invalid_cloud_id".to_string()),
                    agent: None,
                    timestamp: None,
                    latency_ms: ms(start),
                };
            }

            let agent_value = match data.get("agent") {
                Some(v) => v.clone(),
                None => {
                    return VerificationResult {
                        verified: false,
                        reason: Some("invalid_cloud_id".to_string()),
                        agent: None,
                        timestamp: None,
                        latency_ms: ms(start),
                    }
                }
            };

            let agent: Agent = match serde_json::from_value(agent_value) {
                Ok(a) => a,
                Err(_) => {
                    return VerificationResult {
                        verified: false,
                        reason: Some("registry_error".to_string()),
                        agent: None,
                        timestamp: None,
                        latency_ms: ms(start),
                    }
                }
            };

            if p.cache {
                set_cache(&cloud_id, &agent);
            }

            agent
        }
    };

    // 5. Check agent status
    if agent_data.status != "active" {
        return VerificationResult {
            verified: false,
            reason: Some("agent_suspended".to_string()),
            agent: Some(agent_data),
            timestamp: None,
            latency_ms: ms(start),
        };
    }

    // 6. Check covenant
    if p.require_covenant && !agent_data.covenant_signed {
        return VerificationResult {
            verified: false,
            reason: Some("covenant_unsigned".to_string()),
            agent: Some(agent_data),
            timestamp: None,
            latency_ms: ms(start),
        };
    }

    // 7. Check trust score
    if let Some(min_score) = p.minimum_trust_score {
        match agent_data.trust_score {
            Some(score) if score >= min_score => {}
            _ => {
                return VerificationResult {
                    verified: false,
                    reason: Some("trust_score_insufficient".to_string()),
                    agent: Some(agent_data),
                    timestamp: None,
                    latency_ms: ms(start),
                }
            }
        }
    }

    // 8. Check autonomy level
    if let Some(ref allowed) = p.allowed_autonomy_levels {
        if !allowed.contains(&agent_data.autonomy_level) {
            return VerificationResult {
                verified: false,
                reason: Some("autonomy_level_restricted".to_string()),
                agent: Some(agent_data),
                timestamp: None,
                latency_ms: ms(start),
            };
        }
    }

    // 9. Verify cryptographic signature
    let verifying_key = match parse_public_key(&agent_data.public_key) {
        Ok(k) => k,
        Err(_) => {
            return VerificationResult {
                verified: false,
                reason: Some("invalid_signature".to_string()),
                agent: Some(agent_data),
                timestamp: None,
                latency_ms: ms(start),
            }
        }
    };

    let payload = format!("{}:{}", cloud_id, timestamp);
    let sig_bytes = match URL_SAFE_NO_PAD.decode(&signature) {
        Ok(b) => b,
        Err(_) => {
            return VerificationResult {
                verified: false,
                reason: Some("invalid_signature".to_string()),
                agent: Some(agent_data),
                timestamp: None,
                latency_ms: ms(start),
            }
        }
    };

    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => {
            return VerificationResult {
                verified: false,
                reason: Some("invalid_signature".to_string()),
                agent: Some(agent_data),
                timestamp: None,
                latency_ms: ms(start),
            }
        }
    };

    if verifying_key.verify(payload.as_bytes(), &sig).is_err() {
        if let Ok(mut cache) = get_cache().lock() {
            cache.remove(&cloud_id);
        }
        return VerificationResult {
            verified: false,
            reason: Some("invalid_signature".to_string()),
            agent: Some(agent_data),
            timestamp: None,
            latency_ms: ms(start),
        };
    }

    // 10. All checks passed
    VerificationResult {
        verified: true,
        reason: None,
        agent: Some(agent_data),
        timestamp: Some(timestamp),
        latency_ms: ms(start),
    }
}

// ─── Logging ─────────────────────────────────────────────────

fn log_verification(
    registry_url: &str,
    cloud_id: &str,
    result: &str,
    reason: &str,
    latency: f64,
) -> std::result::Result<(), ()> {
    let url = format!("{}/api/verify/log", registry_url.trim_end_matches('/'));

    let body = serde_json::json!({
        "cloud_id": cloud_id,
        "result": result,
        "reason": if reason.is_empty() { None } else { Some(reason) },
        "method": "sdk_headers",
        "latency": latency,
    });

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| ())?;

    let _ = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send();

    Ok(())
}

// ─── Internal helpers ────────────────────────────────────────

fn ms(start: Instant) -> f64 {
    start.elapsed().as_micros() as f64 / 1000.0
}

fn parse_private_key(pem_str: &str) -> Result<SigningKey> {
    let pem_data = pem::parse(pem_str)
        .map_err(|e| CloudError::KeyError(format!("invalid PEM: {}", e)))?;

    // Ed25519 PKCS8 key: the last 32 bytes are the private key
    let der = pem_data.contents();
    if der.len() < 32 {
        return Err(CloudError::KeyError("key too short".to_string()));
    }

    // Extract the 32-byte Ed25519 seed from PKCS8
    // PKCS8 wrapping adds a prefix; the seed is the last 32 bytes
    let seed = &der[der.len() - 32..];
    let key_bytes: [u8; 32] = seed
        .try_into()
        .map_err(|_| CloudError::KeyError("invalid key length".to_string()))?;

    Ok(SigningKey::from_bytes(&key_bytes))
}

fn parse_public_key(pem_str: &str) -> Result<VerifyingKey> {
    let pem_data = pem::parse(pem_str)
        .map_err(|e| CloudError::KeyError(format!("invalid PEM: {}", e)))?;

    let der = pem_data.contents();
    // Ed25519 SPKI public key: last 32 bytes are the public key
    if der.len() < 32 {
        return Err(CloudError::KeyError("key too short".to_string()));
    }

    let key_bytes: [u8; 32] = der[der.len() - 32..]
        .try_into()
        .map_err(|_| CloudError::KeyError("invalid key length".to_string()))?;

    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| CloudError::KeyError(format!("invalid public key: {}", e)))
}

fn fetch_json(url: &str) -> Result<serde_json::Value> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let resp = client.get(url).send()?;
    let status = resp.status();

    if status.as_u16() == 404 {
        return Ok(serde_json::json!({"verified": false}));
    }

    if !status.is_success() {
        return Err(CloudError::RegistryError(format!(
            "registry returned {}",
            status
        )));
    }

    let text = resp.text()?;
    let data: serde_json::Value = serde_json::from_str(&text)?;
    Ok(data)
}
