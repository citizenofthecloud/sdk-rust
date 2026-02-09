# citizenofthecloud

Identity and authentication for autonomous AI agents. Rust SDK.

**Prove who you are. Verify who you're talking to.**

## Install

Add to `Cargo.toml`:

```toml
[dependencies]
citizenofthecloud = "0.1.0"
```

## Quick Start

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

### Generate keys for registration

```rust
use citizenofthecloud::generate_key_pair;

let keys = generate_key_pair().unwrap();
println!("{}", keys.public_key);   // Submit during registration
println!("{}", keys.private_key);  // Keep secret
```

## Features

- Ed25519 cryptographic signatures
- Header-based authentication (compatible with all HTTP clients)
- Request-bound signatures (method + URL + body hash)
- In-memory public key caching with TTL
- Trust policy enforcement (trust score, autonomy level, blocklist)
- Fire-and-forget verification logging
- Thread-safe cache

## License

MIT
