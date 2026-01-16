# tinfoil-rs

A production-ready Rust SDK for [Tinfoil](https://tinfoil.sh) secure enclaves with full cryptographic verification.

## Features

- **Complete Cryptographic Verification** - Every signature in the trust chain is verified
- **ARK Public Key Pinning** - AMD root key fingerprint is hardcoded, preventing MITM attacks
- **TLS Certificate Pinning** - Connections are bound to attested enclave certificates
- **Full Sigstore Verification** - DSSE signatures prove code came from GitHub Actions
- **No OpenSSL** - Pure Rust cryptography, no system dependencies
- **OpenAI-Compatible API** - Drop-in replacement for chat and embedding endpoints

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
tinfoil = { git = "https://github.com/anthropics/tinfoil-rs" }
```

## Quick Start

```rust
use tinfoil::{attestation, sigstore, SecureClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Verify hardware attestation
    let doc = attestation::fetch("inference.tinfoil.sh").await?;
    let enclave = attestation::verify_full(&doc).await?;
    println!("✓ Hardware attestation verified");
    
    // Step 2: Verify code provenance
    let source = sigstore::verify_repo("tinfoilsh/model-repo").await?;
    println!("✓ Sigstore verification passed");
    
    // Step 3: Compare measurements
    enclave.measurement.equals(&source)?;
    println!("✓ Enclave runs published code");
    
    // Create verified client and make requests
    let mut client = SecureClient::new("inference.tinfoil.sh", "your-api-key");
    client.verify().await?;
    
    let response = client.chat(vec![
        tinfoil::ChatMessage::user("What is 2+2?")
    ]).await?;
    
    println!("Response: {}", response.choices[0].message.content);
    Ok(())
}
```

## Three-Step Verification

### Step 1: Hardware Attestation (AMD SEV-SNP)

Verifies the enclave runs on genuine AMD hardware with encrypted memory:

- **ARK pinning** - AMD root key fingerprint is hardcoded
- **ARK self-signature** - RSA-PSS SHA-384 verified
- **ASK signature** - Verified against ARK
- **VCEK signature** - Verified against ASK  
- **Report signature** - ECDSA P-384 verified against VCEK

```rust
let doc = attestation::fetch("inference.tinfoil.sh").await?;
let enclave = attestation::verify_full(&doc).await?;
// enclave.measurement, enclave.tls_public_key_fp, enclave.hpke_public_key
```

### Step 2: Sigstore Verification (Code Provenance)

Proves the code was built by GitHub Actions from the public repository:

- **DSSE signature** - ECDSA P-256 over PAE-encoded payload
- **Certificate validation** - Issuer must be GitHub Actions
- **Repository check** - Certificate must be for expected repo

```rust
let measurement = sigstore::verify_repo("tinfoilsh/model-repo").await?;
```

### Step 3: TLS Certificate Pinning

Binds connections to the attested enclave, preventing MITM attacks:

- **SPKI fingerprint** - SHA-256 of certificate's SubjectPublicKeyInfo
- **Chain validation** - Standard CA verification still applies

```rust
let mut client = SecureClient::new("inference.tinfoil.sh", "api-key");
client.verify().await?;  // Sets up pinned TLS
// All subsequent requests use pinned connection
```

## Security Model

When verification passes, you have cryptographic proof that:

| Guarantee | How It's Verified |
|-----------|-------------------|
| Hardware is genuine | AMD ARK signature chain (pinned root) |
| Memory is encrypted | SEV-SNP attestation |
| Code is auditable | Sigstore measurement matches |
| Build is legitimate | GitHub Actions certificate |
| Connection is secure | TLS pinned to attested key |

**An attacker would need AMD's private keys to forge attestation.** That's the correct security model.

## API Reference

### Attestation

```rust
// Fetch attestation document
let doc = attestation::fetch("host.tinfoil.sh").await?;

// Full verification with certificate chain
let enclave = attestation::verify_full(&doc).await?;
```

### Sigstore

```rust
// Full cryptographic verification
let measurement = sigstore::verify_repo("org/repo").await?;

// Individual steps (if needed)
let tag = sigstore::fetch_latest_tag("org/repo").await?;
let digest = sigstore::fetch_digest("org/repo", &tag).await?;
```

### SecureClient

```rust
let mut client = SecureClient::new("inference.tinfoil.sh", "api-key");
client.verify().await?;

// Chat API
let response = client.chat(vec![
    ChatMessage::system("You are helpful"),
    ChatMessage::user("Hello!")
]).await?;

// Embedding API
let embedding = client.embed("text to embed").await?;
```

## Examples

Run the full verification demo:

```bash
cargo run --example full_verification
```

Test the API with TLS pinning:

```bash
export TINFOIL_API_KEY="your-api-key"
cargo run --example test_api
```

## Cryptographic Details

| Component | Algorithm | Key Size |
|-----------|-----------|----------|
| AMD ARK/ASK/VCEK chain | RSA-PSS | 4096-bit |
| SNP Report signature | ECDSA | P-384 |
| Sigstore DSSE | ECDSA | P-256 |
| TLS/ARK pinning | SHA-256 | 256-bit |

## Requirements

- Rust 1.70+
- No system dependencies (pure Rust crypto)

## License

MIT

## Contributing

Contributions welcome! Please ensure all tests pass:

```bash
cargo test
cargo run --example full_verification
```
