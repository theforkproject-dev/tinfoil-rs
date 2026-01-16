# tinfoil-rs

A production-ready Rust SDK for [Tinfoil](https://tinfoil.sh) secure enclaves with full cryptographic verification.

## Features

- **Complete Cryptographic Verification** - Every signature in the trust chain is verified
- **ARK Public Key Pinning** - AMD root key fingerprint is hardcoded, preventing MITM attacks
- **TLS Certificate Pinning** - Connections are bound to attested enclave certificates
- **Full Sigstore Verification** - DSSE signatures prove code came from GitHub Actions
- **No OpenSSL** - Pure Rust cryptography, no system dependencies
- **OpenAI-Compatible API** - Drop-in replacement for chat, embedding, and document endpoints

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
tinfoil = { git = "https://github.com/theforkproject-dev/tinfoil-rs" }
```

## Architecture

Tinfoil uses a **Confidential Model Router** architecture:

```
Client → Confidential Model Router (enclave) → Model Enclaves (enclaves)
         inference.tinfoil.sh                   qwen3-coder, nomic-embed, etc.
```

Both the router AND model enclaves run in AMD SEV-SNP secure enclaves. When you verify `inference.tinfoil.sh`, you're verifying the router which internally verifies each model enclave before routing requests.

**Router Repository:** [`tinfoilsh/confidential-model-router`](https://github.com/tinfoilsh/confidential-model-router)

## Quick Start

```rust
use tinfoil::{attestation, sigstore, SecureClient, ChatMessage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Verify the router enclave hardware
    let doc = attestation::fetch("inference.tinfoil.sh").await?;
    let enclave = attestation::verify_full(&doc).await?;
    println!("✓ Hardware attestation verified");
    
    // Step 2: Verify router code provenance
    let source = sigstore::verify_repo("tinfoilsh/confidential-model-router").await?;
    println!("✓ Sigstore verification passed");
    
    // Step 3: Compare measurements
    enclave.measurement.equals(&source)?;
    println!("✓ Router runs published code");
    
    // Create verified client - all requests go through attested router
    let mut client = SecureClient::new("inference.tinfoil.sh", "your-api-key");
    client.verify().await?;
    
    // Chat with qwen3-coder-480b
    let response = client.chat_with_model("qwen3-coder-480b", vec![
        ChatMessage::user("What is 2+2?")
    ], None).await?;
    println!("Response: {}", response.choices[0].message.content);
    
    // Generate embeddings with nomic-embed-text
    let embedding = client.embed("text to embed").await?;
    println!("Embedding: {} dimensions", embedding.len());
    
    Ok(())
}
```

## Supported Models

All requests go through the verified router at `inference.tinfoil.sh`:

| Model ID | Type | Use Case |
|----------|------|----------|
| `qwen3-coder-480b` | Chat/Code | Advanced coding, 480B MoE (35B active), 128K context |
| `nomic-embed-text` | Embedding | Semantic search, 768 dimensions, 8K context |
| `docling` | Document | PDF/Word processing, text extraction |
| `llama3-3-70b` | Chat | General conversation, 128K context |
| `deepseek-r1-0528` | Chat | Advanced reasoning, 671B parameters |
| `qwen3-vl-30b` | Vision | Image/video analysis, 256K context |
| `whisper-large-v3-turbo` | Audio | Speech-to-text transcription |

See [Tinfoil Model Catalog](https://docs.tinfoil.sh/models/catalog) for full details.

## Three-Step Verification

### Step 1: Hardware Attestation (AMD SEV-SNP)

Verifies the router enclave runs on genuine AMD hardware with encrypted memory:

- **ARK pinning** - AMD root key fingerprint is hardcoded
- **ARK self-signature** - RSA-PSS SHA-384 verified
- **ASK signature** - Verified against ARK
- **VCEK signature** - Verified against ASK  
- **Report signature** - ECDSA P-384 verified against VCEK

```rust
let doc = attestation::fetch("inference.tinfoil.sh").await?;
let enclave = attestation::verify_full(&doc).await?;
```

### Step 2: Sigstore Verification (Code Provenance)

Proves the router code was built by GitHub Actions:

- **DSSE signature** - ECDSA P-256 over PAE-encoded payload
- **Certificate validation** - Issuer must be GitHub Actions
- **Repository check** - Must be `tinfoilsh/confidential-model-router`

```rust
let source = sigstore::verify_repo("tinfoilsh/confidential-model-router").await?;
enclave.measurement.equals(&source)?;
```

### Step 3: TLS Certificate Pinning

Binds connections to the attested router, preventing MITM attacks:

```rust
let mut client = SecureClient::new("inference.tinfoil.sh", "api-key");
client.verify().await?;  // Sets up pinned TLS
// All subsequent requests use pinned connection to verified router
```

## Chain of Trust

When verification passes:

1. **You verify the router** - AMD hardware attestation + Sigstore code provenance
2. **Router verifies model enclaves** - Internal attestation before routing
3. **End-to-end encryption** - TLS pinned to attested certificates

Your data flows through verified enclaves at every step. Not even Tinfoil can access your prompts or responses.

## API Reference

### Chat (qwen3-coder-480b)

```rust
let response = client.chat_with_model("qwen3-coder-480b", vec![
    ChatMessage::system("You are a helpful coding assistant"),
    ChatMessage::user("Write a Rust function to sort a vector")
], None).await?;
```

### Embeddings (nomic-embed-text)

```rust
let embedding = client.embed("text to generate embedding for").await?;
// Returns Vec<f32> with 768 dimensions
```

### Document Processing (docling)

```rust
// Coming soon - document upload and processing API
```

## Security Model

| Guarantee | How It's Verified |
|-----------|-------------------|
| Hardware is genuine | AMD ARK signature chain (pinned root) |
| Memory is encrypted | SEV-SNP attestation |
| Router code is auditable | Sigstore measurement matches |
| Build is legitimate | GitHub Actions certificate |
| Connection is secure | TLS pinned to attested key |
| Model enclaves verified | Router performs internal attestation |

**An attacker would need AMD's private keys to forge attestation.**

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

## Related

- [Tinfoil Documentation](https://docs.tinfoil.sh)
- [Confidential Model Router](https://github.com/tinfoilsh/confidential-model-router)
- [Tinfoil Verifier (Go)](https://github.com/tinfoilsh/verifier)
