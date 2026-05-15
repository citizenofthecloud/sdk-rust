# citizenofthecloud — Rust SDK

Identity and authentication for autonomous AI agents. Rust SDK.

**Prove who you are. Verify who you're talking to.**

Exposes the full **17-tool Citizen of the Cloud surface** — registration, signing, verification, the challenge/respond loop, registry queries, and an Axum route-guard middleware (behind the `axum` feature flag).

---

## Install

```toml
# Cargo.toml — directly from GitHub (recommended while crates.io catches up)
[dependencies]
citizenofthecloud = { git = "https://github.com/citizenofthecloud/sdk-rust", branch = "main" }

# With the Axum route-guard middleware enabled:
citizenofthecloud = { git = "...", features = ["axum"] }
```

```rust
use citizenofthecloud as cotc;
```

Requires Rust 1.75+.

---

## The 17-tool surface

| # | Tool | API | Purpose |
|---|---|---|---|
| 1 | lookup-agent | `cotc::lookup_agent(registry_url, cloud_id)` | Read another agent's passport |
| 2 | get-server-identity | `identity.get_passport()` | Fetch your own passport |
| 3 | list-directory | `cotc::list_directory(registry_url)` | Browse the public directory |
| 4 | governance-feed | `cotc::get_governance_feed(registry_url)` | Read recent registry events |
| 5 | verify-agent | `cotc::verify_agent(headers, &policy)` | Verify signed headers (simple) |
| 6 | verify-request | `cotc::verify_request(headers, url, method, body, &policy)` | Verify request-bound signature |
| 7 | request-challenge | `cotc::request_challenge(registry_url, cloud_id)` | Ask the registry for a nonce |
| 8 | respond-to-challenge | `cotc::submit_challenge_response(...)` | Submit a signed nonce |
| 9 | prove-identity | `identity.prove_identity()` | Full challenge/sign/respond loop |
| 10 | sign-headers | `identity.sign()` | Produce timestamp-bound headers |
| 11 | sign-request | `identity.sign_request(url, method, body)` | Produce request-bound headers |
| 12 | cloud-fetch | `cotc::cloud_fetch(&identity, url, method, body)` | Auto-signed HTTP request |
| 13 | generate-keypair | `cotc::generate_key_pair()` | Make a fresh Ed25519 keypair |
| 14 | trust-policy | `cotc::TrustPolicy { .. }` | Reusable verification rules |
| 15 | clear-cache | `cotc::clear_cache()` | Clear the verification cache |
| 16 | http-middleware | `cotc::axum::cloud_guard(policy)` (feature `axum`) | Axum route guard |
| 17 | register-agent | `cotc::register_agent(sdk_token, opts)` | Programmatic agent registration |

---

## Quick start (register → sign → verify)

```rust
use citizenofthecloud as cotc;
use std::env;

fn main() -> cotc::Result<()> {
    // 1. Register a new agent (one-time; needs an SDK token from /account)
    let reg = cotc::register_agent(
        &env::var("COTC_SDK_TOKEN").unwrap(),
        cotc::RegisterOptions {
            name: "My Research Bot".into(),
            declared_purpose: "Summarize papers and surface trends".into(),
            autonomy_level: "tool".into(),
            ..Default::default()
        },
    )?;
    println!("Cloud ID: {}", reg.cloud_id);
    println!("Private key — STORE SECURELY:\n{}", reg.private_key);

    // 2. Sign an outbound request
    let me = cotc::CloudIdentity::new(cotc::Config {
        cloud_id: reg.cloud_id.clone(),
        private_key: reg.private_key.clone(),
        ..Default::default()
    })?;
    let headers = me.sign()?;
    // attach headers to your reqwest / ureq / hyper request...

    // 3. On the receiving side — verify an inbound request
    let policy = cotc::TrustPolicy { minimum_trust_score: Some(0.5), ..Default::default() };
    let result = cotc::verify_agent(&inbound_headers, &policy)?;
    if result.verified {
        println!("Verified: {} (trust {:?})", result.agent.unwrap().name, result.agent.unwrap().trust_score);
    }
    Ok(())
}
```

---

## Examples per surface

### Key management (#13 generate-keypair)

```rust
let keys = cotc::generate_key_pair()?;
// keys.public_key  → submit during manual registration
// keys.private_key → keep secret
```

### Registration (#17 register-agent)

```rust
let reg = cotc::register_agent(
    &env::var("COTC_SDK_TOKEN").unwrap(),
    cotc::RegisterOptions {
        name: "My Research Bot".into(),
        declared_purpose: "Summarize papers and surface trends".into(),
        autonomy_level: "tool".into(),    // "tool" | "assistant" | "agent" | "self-directing"
        capabilities: Some(vec!["summarize".into(), "cite".into()]),
        operational_domain: Some("research-lab.example.com".into()),
        ..Default::default()
    },
)?;
```

### Outbound signing (#10, #11, #12)

```rust
let me = cotc::CloudIdentity::new(cotc::Config {
    cloud_id: env::var("CLOUD_ID")?,
    private_key: env::var("CLOUD_PRIVATE_KEY")?,
    ..Default::default()
})?;

// 10 — simple
let headers = me.sign()?;

// 11 — request-bound (signs URL + method + body hash too)
let req_headers = me.sign_request("https://other.example.com/api/data", "POST", r#"{"q":"x"}"#)?;

// 12 — convenience: HTTP call with auto-signed request-bound headers
let resp = cotc::cloud_fetch(&me, "https://other.example.com/api/data", "POST", Some(r#"{"q":"x"}"#))?;
```

### Inbound verification (#5, #6, #14)

```rust
let policy = cotc::TrustPolicy {
    minimum_trust_score: Some(0.5),
    require_covenant: true,
    allowed_autonomy_levels: Some(vec!["agent".into(), "assistant".into()]),
    ..Default::default()
};

// 5 — simple
let r1 = cotc::verify_agent(&headers, &policy)?;

// 6 — request-bound
let r2 = cotc::verify_request(&headers, &request_url, request_method, &body_str, &policy)?;

if !r2.verified {
    return Err(/* 401 */);
}
println!("Verified {}", r2.agent.unwrap().name);
```

### Challenge / Respond (#7, #8, #9 prove-identity)

```rust
let me = cotc::CloudIdentity::new(cotc::Config { cloud_id, private_key, ..Default::default() })?;

// 9 — full self-prove loop in one call (recommended)
let verified = me.prove_identity()?;
assert!(verified.verified);

// Or — compose manually:
// 7
let ch = cotc::request_challenge("https://citizenofthecloud.com", &cloud_id)?;
// 8 — pass your base64 signature over the UTF-8 nonce bytes
let result = cotc::submit_challenge_response(
    "https://citizenofthecloud.com", &cloud_id, &ch.nonce, &signature_b64,
)?;
```

### Registry queries (#1, #2, #3, #4)

```rust
// 1 — Look up another agent
let agent = cotc::lookup_agent("https://citizenofthecloud.com", "cc-abc...")?;

// 2 — Fetch your own passport
let me = cotc::CloudIdentity::new(cotc::Config { cloud_id, private_key, ..Default::default() })?;
let my = me.get_passport()?;

// 3 — Browse the public directory
let all = cotc::list_directory("https://citizenofthecloud.com")?;

// 4 — Read the governance event feed
let feed = cotc::get_governance_feed("https://citizenofthecloud.com")?;
```

#### Reading the reputation block (Layer 3)

`lookup_agent()` now surfaces a `reputation` field alongside the composite `trust_score`.
The composite stays at `agent.trust_score`; the component signals live at `agent.reputation`
and let relying parties weight inputs against their own use case. Signals refresh every 5 minutes;
a freshly registered agent may return `reputation: None` — treat None as "not enough data yet,"
not as "zero across all signals."

```rust
let agent = cotc::lookup_agent("https://citizenofthecloud.com", "cc-abc...")?;

// Composite — fast threshold check
if agent.trust_score.unwrap_or(0.0) >= 0.5 {
    // ...
}

// Components — identity-strength preference (require cryptographic proofs)
if let Some(rep) = &agent.reputation {
    if rep.authenticated_proofs >= 1 && rep.success_rate_lifetime >= 0.9 {
        accept(&agent);
    }
}

// Hard-reject on any upheld report, regardless of composite
if let Some(rep) = &agent.reputation {
    if rep.reports_upheld >= 1 {
        return Err("agent has upheld governance reports".into());
    }
}
```

### Axum route guard (#16 http-middleware, feature `axum`)

Enable the feature in your `Cargo.toml`:

```toml
[dependencies]
citizenofthecloud = { git = "...", features = ["axum"] }
```

```rust
use axum::{Router, routing::post};
use citizenofthecloud::axum::cloud_guard;
use citizenofthecloud::TrustPolicy;

let app = Router::new()
    .route("/api/task", post(handler))
    .layer(cloud_guard(TrustPolicy {
        minimum_trust_score: Some(0.5),
        ..Default::default()
    }));
```

### Cache control (#15 clear-cache)

```rust
cotc::clear_cache();   // useful in tests / after a trust-score update
```

---

## Environment variables

| Variable | Description |
|---|---|
| `CLOUD_ID` | Your agent's Cloud ID (e.g., `cc-7f3a9b2e-...`) |
| `CLOUD_PRIVATE_KEY` | Your agent's Ed25519 private key (PEM format) |
| `COTC_SDK_TOKEN` | Bootstrap SDK token (`cotc_sdk_*`) for `register_agent`. Get one at [citizenofthecloud.com/account](https://citizenofthecloud.com/account). |

---

## Links

- [citizenofthecloud.com](https://citizenofthecloud.com)
- [Documentation](https://citizenofthecloud.com/docs)
- [Specification](https://citizenofthecloud.com/spec)
- [Account / SDK tokens](https://citizenofthecloud.com/account)
- Sister SDKs: [sdk-js](https://github.com/citizenofthecloud/sdk-js) · [sdk-python](https://github.com/citizenofthecloud/sdk-python) · [sdk-go](https://github.com/citizenofthecloud/sdk-go)
- [MCP server](https://github.com/citizenofthecloud/mcp-server)

## License

MIT
