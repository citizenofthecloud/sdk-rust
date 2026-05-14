//! # citizenofthecloud
//!
//! Identity and authentication for autonomous AI agents.
//!
//! **Prove who you are. Verify who you're talking to.**
//!
//! ## Quick Start
//!
//! ```no_run
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
//! let headers = identity.sign().to_map();
//!
//! // Verify inbound requests
//! let result = verify_agent(&headers, None);
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
    // Optional because /api/directory redacts the public key for listings;
    // /api/verify (single-agent lookup) and registration responses include it.
    pub public_key: Option<String>,
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
    /// Use this instead of `sign()` to bind the signature to a specific HTTP
    /// request — prevents replay against different endpoints if headers leak.
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

    /// Prove this agent's identity via the full challenge/respond cryptographic
    /// loop. Requests a nonce from the registry, signs it with the private key,
    /// submits the response, and returns the verification result. The resulting
    /// verification_log row is server-witnessed (authenticated=true) and
    /// contributes to this agent's trust score.
    pub fn prove_identity(&self) -> Result<VerificationResult> {
        use base64::engine::general_purpose::STANDARD;
        let challenge = request_challenge(&self.registry_url, &self.cloud_id)?;
        // Server signs over the UTF-8 bytes of the hex nonce string (not the
        // decoded hex bytes) — see registry's lib/verification.js.
        let signature = self.signing_key.sign(challenge.nonce.as_bytes());
        let sig_b64 = STANDARD.encode(signature.to_bytes());
        submit_challenge_response(&self.registry_url, &self.cloud_id, &challenge.nonce, &sig_b64)
    }
}

// ─── Challenge / Respond ─────────────────────────────────────

/// Holds a nonce returned from `/api/verify/challenge`.
#[derive(Debug, Clone, Deserialize)]
pub struct ChallengeResult {
    pub nonce: String,
    pub expires_in: u64,
}

/// Request a verification challenge for `cloud_id` from the registry. The
/// returned nonce must be signed with the agent's private key (over the UTF-8
/// bytes of the hex string) and submitted via `submit_challenge_response`.
pub fn request_challenge(registry_url: &str, cloud_id: &str) -> Result<ChallengeResult> {
    let url = format!("{}/api/verify/challenge", registry_url.trim_end_matches('/'));
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let body = serde_json::json!({ "cloud_id": cloud_id });
    let resp = client.post(&url).json(&body).send()?;
    let status = resp.status();
    let text = resp.text()?;

    if !status.is_success() {
        if let Ok(err_json) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(msg) = err_json.get("error").and_then(|v| v.as_str()) {
                return Err(CloudError::RegistryError(msg.to_string()));
            }
        }
        return Err(CloudError::RegistryError(format!(
            "challenge request failed: {}",
            status
        )));
    }

    let result: ChallengeResult = serde_json::from_str(&text)?;
    Ok(result)
}

/// Submit a signed challenge response. The registry validates the signature
/// against the agent's registered public key and returns the verified agent.
/// `signature` must be standard base64-encoded (not URL-safe).
pub fn submit_challenge_response(
    registry_url: &str,
    cloud_id: &str,
    nonce: &str,
    signature: &str,
) -> Result<VerificationResult> {
    let url = format!("{}/api/verify/respond", registry_url.trim_end_matches('/'));
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let body = serde_json::json!({
        "cloud_id": cloud_id,
        "nonce": nonce,
        "signature": signature,
    });
    let resp = client.post(&url).json(&body).send()?;
    let text = resp.text()?;

    // respond returns non-2xx for failed verification but still includes a
    // parseable body — parse it as a VerificationResult either way.
    let raw: serde_json::Value = serde_json::from_str(&text)?;
    let verified = raw.get("verified").and_then(|v| v.as_bool()).unwrap_or(false);
    let reason = raw
        .get("error")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let timestamp = raw
        .get("timestamp")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let agent = raw
        .get("agent")
        .and_then(|v| serde_json::from_value::<Agent>(v.clone()).ok());

    Ok(VerificationResult {
        verified,
        reason,
        agent,
        timestamp,
        latency_ms: 0.0,
    })
}

// ─── Registry queries (no auth) ──────────────────────────────

/// Look up an agent's public record by cloud_id.
/// Returns `Ok(None)` if the agent is not found.
pub fn lookup_agent(registry_url: &str, cloud_id: &str) -> Result<Option<Agent>> {
    let url = format!(
        "{}/api/verify?cloud_id={}",
        registry_url.trim_end_matches('/'),
        urlencoding::encode(cloud_id)
    );
    let data = fetch_json(&url)?;
    if !data.get("verified").and_then(|v| v.as_bool()).unwrap_or(false) {
        return Ok(None);
    }
    let agent_value = match data.get("agent") {
        Some(v) => v.clone(),
        None => return Ok(None),
    };
    let agent: Agent = serde_json::from_value(agent_value)?;
    Ok(Some(agent))
}

/// List the public agent directory.
pub fn list_directory(registry_url: &str) -> Result<Vec<Agent>> {
    let url = format!("{}/api/directory", registry_url.trim_end_matches('/'));
    let data = fetch_json(&url)?;
    let agents_value = data
        .get("agents")
        .ok_or_else(|| CloudError::RegistryError("no agents in response".to_string()))?;
    let agents: Vec<Agent> = serde_json::from_value(agents_value.clone())?;
    Ok(agents)
}

/// Get the governance activity feed.
pub fn get_governance_feed(registry_url: &str) -> Result<Vec<serde_json::Value>> {
    let url = format!("{}/api/governance/feed", registry_url.trim_end_matches('/'));
    let data = fetch_json(&url)?;
    let feed = data
        .get("feed")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    Ok(feed)
}

// ─── Registration (SDK token auth) ───────────────────────────

/// Options for [`register_agent`].
#[derive(Debug, Clone, Default)]
pub struct RegisterOptions {
    pub name: String,
    pub declared_purpose: String,
    /// 'tool' | 'assistant' | 'agent' | 'self-directing'. Defaults to "tool" if empty.
    pub autonomy_level: String,
    pub capabilities: Vec<String>,
    pub operational_domain: Option<String>,
    pub covenant_signed: bool,
    /// Registry base URL. Defaults to [`DEFAULT_REGISTRY`] if empty.
    pub registry_url: String,
}

/// Result returned by [`register_agent`]. The `private_key` is yours to
/// keep — it is generated locally and never sent to the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResult {
    pub cloud_id: String,
    pub public_key: String,
    pub private_key: String,
    pub name: String,
    pub declared_purpose: String,
    pub autonomy_level: String,
    #[serde(default)]
    pub passport: Option<serde_json::Value>,
}

/// Register a new agent in a single call. Generates a fresh Ed25519 keypair
/// locally, posts the public key plus the agent metadata to the registry
/// under the supplied SDK token, and returns the cloud_id with both keys.
///
/// `sdk_token` must be a "cotc_sdk_*" token issued from the user's account
/// at citizenofthecloud.com/account.
pub fn register_agent(sdk_token: &str, opts: RegisterOptions) -> Result<RegisterResult> {
    if !sdk_token.starts_with("cotc_sdk_") {
        return Err(CloudError::SDKError(
            "sdk_token must be a cotc_sdk_* token. Create one at citizenofthecloud.com/account.".into(),
        ));
    }

    let autonomy_level = if opts.autonomy_level.is_empty() {
        "tool".to_string()
    } else {
        opts.autonomy_level.clone()
    };
    let registry = if opts.registry_url.is_empty() {
        DEFAULT_REGISTRY.to_string()
    } else {
        opts.registry_url.clone()
    };

    let kp = generate_key_pair()?;

    let mut payload = serde_json::json!({
        "name": opts.name,
        "declared_purpose": opts.declared_purpose,
        "autonomy_level": autonomy_level,
        "public_key": kp.public_key,
        "covenant_signed": opts.covenant_signed,
        "capabilities": opts.capabilities,
    });
    if let Some(domain) = &opts.operational_domain {
        payload["operational_domain"] = serde_json::Value::String(domain.clone());
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let resp = client
        .post(format!(
            "{}/api/register",
            registry.trim_end_matches('/')
        ))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", sdk_token))
        .body(payload.to_string())
        .send()?;

    let status = resp.status();
    let body_text = resp.text()?;
    if !status.is_success() {
        let err_msg = serde_json::from_str::<serde_json::Value>(&body_text)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|x| x.as_str())
                    .or_else(|| v.get("error_code").and_then(|x| x.as_str()))
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| format!("HTTP {}", status));
        return Err(CloudError::RegistryError(format!(
            "Registration failed: {}",
            err_msg
        )));
    }

    let data: serde_json::Value = serde_json::from_str(&body_text)?;
    let cloud_id = data
        .get("cloud_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CloudError::RegistryError("missing cloud_id in response".into()))?
        .to_string();

    Ok(RegisterResult {
        cloud_id,
        public_key: kp.public_key,
        private_key: kp.private_key,
        name: opts.name,
        declared_purpose: opts.declared_purpose,
        autonomy_level,
        passport: data.get("passport").cloned(),
    })
}

// ─── Cloud fetch (signed outbound) ───────────────────────────

/// Make a signed HTTP request to another agent's endpoint. Auto-signs the
/// request with the given identity's key. Returns the reqwest::blocking::Response
/// so the caller can read the body and status.
pub fn cloud_fetch(
    identity: &CloudIdentity,
    url: &str,
    method: &str,
    body: &str,
) -> Result<reqwest::blocking::Response> {
    let headers = identity.sign_request(url, method, body);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let method_upper = method.to_uppercase();
    let mut req = match method_upper.as_str() {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        "PATCH" => client.patch(url),
        _ => {
            return Err(CloudError::SDKError(format!(
                "unsupported HTTP method: {}",
                method
            )))
        }
    };

    req = req
        .header("X-Cloud-ID", &headers.cloud_id)
        .header("X-Cloud-Timestamp", &headers.timestamp)
        .header("X-Cloud-Signature", &headers.signature)
        .header("X-Cloud-Request-Bound", "true");

    if !body.is_empty() {
        req = req
            .header("Content-Type", "application/json")
            .body(body.to_string());
    }

    Ok(req.send()?)
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
    let pk = match agent_data.public_key.as_deref() {
        Some(s) => s,
        None => {
            return VerificationResult {
                verified: false,
                reason: Some("invalid_signature".to_string()),
                agent: Some(agent_data),
                timestamp: None,
                latency_ms: ms(start),
            }
        }
    };
    let verifying_key = match parse_public_key(pk) {
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

/// Verify incoming request headers with request-bound signature validation.
///
/// Validates the signature over `{cloud_id}:{timestamp}:{method}:{url}:{body_hash}`
/// (stricter than `verify_agent` which only validates `{cloud_id}:{timestamp}`).
/// Use this on routes where you want to bind signatures to a specific request
/// and prevent replay against different endpoints if headers leak.
///
/// Falls back to `verify_agent` if the request does not carry the
/// `X-Cloud-Request-Bound` marker.
pub fn verify_request(
    headers: &HashMap<String, String>,
    url: &str,
    method: &str,
    body: &str,
    policy: Option<&TrustPolicy>,
) -> VerificationResult {
    let start = Instant::now();

    let get = |name: &str| -> Option<String> {
        headers
            .get(name)
            .or_else(|| headers.get(&name.to_lowercase()))
            .cloned()
    };

    if get("X-Cloud-Request-Bound").is_none() {
        return verify_agent(headers, policy);
    }

    // Run policy + lookup via verify_agent. If it fails for any reason other
    // than signature mismatch, return that result — only the signature is
    // expected to fail (because verify_agent uses the simple-payload signature).
    let basic = verify_agent(headers, policy);
    if !basic.verified && basic.reason.as_deref() != Some("invalid_signature") {
        return basic;
    }

    let agent = match basic.agent {
        Some(a) => a,
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

    let (cloud_id, timestamp, signature) = match (
        get("X-Cloud-ID"),
        get("X-Cloud-Timestamp"),
        get("X-Cloud-Signature"),
    ) {
        (Some(c), Some(t), Some(s)) => (c, t, s),
        _ => {
            return VerificationResult {
                verified: false,
                reason: Some("missing_headers".to_string()),
                agent: Some(agent),
                timestamp: None,
                latency_ms: ms(start),
            }
        }
    };

    let pk = match agent.public_key.as_deref() {
        Some(s) => s,
        None => {
            return VerificationResult {
                verified: false,
                reason: Some("invalid_signature".to_string()),
                agent: Some(agent),
                timestamp: None,
                latency_ms: ms(start),
            }
        }
    };
    let verifying_key = match parse_public_key(pk) {
        Ok(k) => k,
        Err(_) => {
            return VerificationResult {
                verified: false,
                reason: Some("invalid_signature".to_string()),
                agent: Some(agent),
                timestamp: None,
                latency_ms: ms(start),
            }
        }
    };

    let body_hash = Sha256::digest(body.as_bytes());
    let body_hash_b64 = URL_SAFE_NO_PAD.encode(body_hash);
    let payload = format!(
        "{}:{}:{}:{}:{}",
        cloud_id,
        timestamp,
        method.to_uppercase(),
        url,
        body_hash_b64
    );

    let sig_bytes = match URL_SAFE_NO_PAD.decode(&signature) {
        Ok(b) => b,
        Err(_) => {
            return VerificationResult {
                verified: false,
                reason: Some("invalid_signature".to_string()),
                agent: Some(agent),
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
                agent: Some(agent),
                timestamp: None,
                latency_ms: ms(start),
            }
        }
    };

    if verifying_key.verify(payload.as_bytes(), &sig).is_err() {
        return VerificationResult {
            verified: false,
            reason: Some("invalid_signature".to_string()),
            agent: Some(agent),
            timestamp: None,
            latency_ms: ms(start),
        };
    }

    VerificationResult {
        verified: true,
        reason: None,
        agent: Some(agent),
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

// ─── Axum middleware (feature-gated) ─────────────────────────
//
// Enable with `--features axum` in your Cargo.toml:
//   citizenofthecloud = { version = "...", features = ["axum"] }
//
// Then use `cloud_guard` as an axum middleware layer to verify inbound
// Cloud-signed requests before they reach your handler. The verified
// Agent is attached to the request's extensions so the handler can pull
// it out with `Extension<Agent>`.

#[cfg(feature = "axum")]
pub mod axum_middleware {
    use super::{verify_agent, TrustPolicy};
    use axum::{
        body::Body,
        extract::Request,
        http::{HeaderMap, StatusCode},
        middleware::Next,
        response::{IntoResponse, Response},
    };
    use std::collections::HashMap;

    /// Axum middleware that verifies inbound Cloud-signed requests.
    ///
    /// On success, attaches the verified `Agent` to request extensions.
    /// On failure, responds with 401 and a JSON error body.
    ///
    /// # Example
    /// ```ignore
    /// use axum::{Router, middleware, routing::get};
    /// use citizenofthecloud::axum_middleware::cloud_guard;
    ///
    /// let app: Router = Router::new()
    ///     .route("/protected", get(handler))
    ///     .layer(middleware::from_fn(cloud_guard));
    /// ```
    pub async fn cloud_guard(mut req: Request, next: Next) -> Response {
        let headers_map = headers_to_map(req.headers());
        // verify_agent uses reqwest::blocking internally; running it directly
        // inside an async handler panics (nested-runtime). Hand it to a
        // blocking thread so axum workers stay non-blocking.
        let result = match tokio::task::spawn_blocking(move || verify_agent(&headers_map, None))
            .await
        {
            Ok(r) => r,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("content-type", "application/json")],
                    r#"{"error":"verify_join_error"}"#,
                )
                    .into_response();
            }
        };

        if !result.verified {
            let reason = result.reason.unwrap_or_else(|| "unauthorized".to_string());
            let body = format!(r#"{{"error":"{}"}}"#, reason);
            return (
                StatusCode::UNAUTHORIZED,
                [("content-type", "application/json")],
                body,
            )
                .into_response();
        }

        if let Some(agent) = result.agent {
            req.extensions_mut().insert(agent);
        }

        next.run(req).await
    }

    /// Axum middleware with a custom `TrustPolicy`.
    ///
    /// Returns a closure suitable for `middleware::from_fn_with_state` or
    /// `middleware::from_fn` after partial application.
    pub fn cloud_guard_with_policy(
        policy: TrustPolicy,
    ) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
           + Clone {
        move |mut req: Request, next: Next| {
            let policy = policy.clone();
            Box::pin(async move {
                let headers_map = headers_to_map(req.headers());
                let result = match tokio::task::spawn_blocking(move || {
                    verify_agent(&headers_map, Some(&policy))
                })
                .await
                {
                    Ok(r) => r,
                    Err(_) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            [("content-type", "application/json")],
                            r#"{"error":"verify_join_error"}"#,
                        )
                            .into_response();
                    }
                };

                if !result.verified {
                    let reason = result.reason.unwrap_or_else(|| "unauthorized".to_string());
                    let body = format!(r#"{{"error":"{}"}}"#, reason);
                    return (
                        StatusCode::UNAUTHORIZED,
                        [("content-type", "application/json")],
                        body,
                    )
                        .into_response();
                }

                if let Some(agent) = result.agent {
                    req.extensions_mut().insert(agent);
                }

                next.run(req).await
            })
        }
    }

    fn headers_to_map(headers: &HeaderMap) -> HashMap<String, String> {
        headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_string(), v.to_string()))
            })
            .collect()
    }

    // Suppress unused-import warning when `Body` isn't directly referenced
    // in the middleware bodies above.
    #[allow(dead_code)]
    type _BodyMarker = Body;
}
