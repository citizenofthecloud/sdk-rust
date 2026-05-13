# citizenofthecloud

Identity and authentication for autonomous AI agents. Rust SDK.

**Prove who you are. Verify who you're talking to.**

## Install

This SDK is currently distributed directly from GitHub. The crates.io release is not yet caught up with the latest features (most recently: `register_agent()` and SDK-token auth). For now, reference the GitHub repo directly in `Cargo.toml`:

```toml
[dependencies]
citizenofthecloud = { git = "https://github.com/citizenofthecloud/sdk-rust" }
```

Optional feature for Axum HTTP middleware:

```toml
[dependencies]
citizenofthecloud = { git = "https://github.com/citizenofthecloud/sdk-rust", features = ["axum"] }
```

A crates.io release will follow once the API stabilizes.

## Quick Start

### Register a new agent (one-time setup)

Bootstrap a new Cloud Identity agent in a single call. Generates a fresh Ed25519 keypair locally, posts the public key to the registry under your SDK token, and returns the `cloud_id` together with both keys. The private key never leaves your process — store it securely.

Get an SDK token from [citizenofthecloud.com/account](https://citizenofthecloud.com/account).

```rust
use citizenofthecloud::{register_agent, RegisterOptions};

fn main() {
    let result = register_agent(
        &std::env::var("COTC_SDK_TOKEN").unwrap(),
        RegisterOptions {
            name: "My Research Bot".to_string(),
            declared_purpose: "Summarize papers and surface trends".to_string(),
            autonomy_level: "tool".to_string(),
            covenant_signed: true,
            ..Default::default()
        },
    ).unwrap();

    println!("{}", result.cloud_id);
    println!("{}", result.public_key);
    println!("{}", result.private_key);   // STORE SECURELY — the server keeps only the public key
}
```

The returned `cloud_id` and `private_key` are the inputs to `CloudIdentity` for signing subsequent requests.

### Sign outbound requests

```rust
use citizenofthecloud::{CloudIdentity, Config};

let identity = CloudIdentity::new(Config {
    cloud_id: std::env::var("CLOUD_ID").unwrap(),
    private_key: std::env::var("CLOUD_PRIVATE_KEY").unwrap(),
    registry_url: None,
}).unwrap();

let headers = identity.sign();

// Use with reqwest
let client = reqwest::blocking::Client::new();
let mut req = client.post("https://other-agent.com/api/task");
for (k, v) in headers.to_map() {
    req = req.header(k, v);
}
let resp = req.send().unwrap();
```

### Verify inbound requests

```rust
use citizenofthecloud::verify_agent;
use std::collections::HashMap;

fn handle_request(headers: &HashMap<String, String>) {
    let result = verify_agent(headers, None);

    if result.verified {
        let agent = result.agent.unwrap();
        println!("Verified: {}", agent.name);
        println!("Trust: {:?}", agent.trust_score);
    } else {
        println!("Rejected: {:?}", result.reason);
    }
}
```

### With Trust Policy

```rust
use citizenofthecloud::{verify_agent, TrustPolicy};

let policy = TrustPolicy {
    minimum_trust_score: Some(0.7),
    allowed_autonomy_levels: Some(vec!["agent".to_string(), "assistant".to_string()]),
    blocked_agents: Some(vec!["cc-known-bad-actor".to_string()]),
    ..Default::default()
};

let result = verify_agent(&headers, Some(&policy));
```

### Generate keys without registering

```rust
use citizenofthecloud::generate_key_pair;

let keys = generate_key_pair().unwrap();
println!("{}", keys.public_key);   // Submit during manual registration
println!("{}", keys.private_key);  // Keep secret
```

## Environment Variables

| Variable | Description |
|---|---|
| `CLOUD_ID` | Your agent's Cloud ID (e.g., `cc-7f3a9b2e-...`) |
| `CLOUD_PRIVATE_KEY` | Your agent's Ed25519 private key (PEM format) |
| `COTC_SDK_TOKEN` | Bootstrap SDK token (`cotc_sdk_*`) for `register_agent()`. Obtain from [citizenofthecloud.com/account](https://citizenofthecloud.com/account). |

## Features

- Ed25519 cryptographic signatures
- Header-based authentication (compatible with all HTTP clients)
- Request-bound signatures (method + URL + body hash)
- In-memory public key caching with TTL
- Trust policy enforcement (trust score, autonomy level, blocklist)
- Fire-and-forget verification logging
- Thread-safe cache
- Optional Axum middleware (feature-gated)

## Links

- [Citizen of the Cloud](https://citizenofthecloud.com)
- [SDK Documentation](https://citizenofthecloud.com/docs)
- [Account / SDK tokens](https://citizenofthecloud.com/account)

## License

MIT
