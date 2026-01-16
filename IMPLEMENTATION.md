# Tinfoil Rust SDK - Implementation Summary

**Repository:** https://github.com/theforkproject-dev/tinfoil-rs

## Project Status: ✅ Production-Ready

A zero-dependency (no OpenSSL) Rust client for Tinfoil secure enclaves with **full cryptographic verification** of both hardware attestation and code provenance.

---

## Architecture

Tinfoil uses a **Confidential Model Router** architecture:

```
Client → Confidential Model Router (enclave) → Model Enclaves
         inference.tinfoil.sh                   qwen3-coder, nomic-embed, docling, etc.
```

- **Router:** `tinfoilsh/confidential-model-router` - Verified by this SDK
- **Models:** Each runs in its own enclave, verified by the router

When you verify the router, you're establishing trust in the entire chain.

---

## Supported Models

| Model ID | Type | Use Case | Context |
|----------|------|----------|---------|
| `qwen3-coder-480b` | Chat/Code | Advanced coding, MoE architecture | 128K |
| `nomic-embed-text` | Embedding | Semantic search, RAG | 8K |
| `docling` | Document | PDF/Word processing | - |
| `llama3-3-70b` | Chat | General conversation | 128K |
| `deepseek-r1-0528` | Chat | Advanced reasoning | 128K |
| `qwen3-vl-30b` | Vision | Image/video analysis | 256K |

---

## Security Highlights

### Full Cryptographic Verification

Every signature in the trust chain is cryptographically verified:

| Component | Algorithm | What It Proves |
|-----------|-----------|----------------|
| ARK self-signature | RSA-PSS SHA-384 | AMD root key is authentic |
| ASK signature | RSA-PSS SHA-384 | AMD SEV key signed by root |
| VCEK signature | RSA-PSS SHA-384 | Chip key signed by SEV key |
| SNP Report | ECDSA P-384 | Report came from this chip |
| DSSE Bundle | ECDSA P-256 | Code signed by GitHub Actions |

### ARK Public Key Pinning

The AMD Root Key (ARK) public key fingerprint is hardcoded:

```rust
const AMD_ARK_GENOA_SPKI_FINGERPRINT: &str = 
    "429a69c9422aa258ee4d8db5fcda9c6470ef15f8cd5a9cebd6cbc7d90b863831";
```

This prevents MITM attacks even if an attacker controls the KDS proxy.

---

## Three-Step Verification Chain

### Step 1: Hardware Attestation (AMD SEV-SNP) ✅

**What it verifies:**
1. ARK public key matches pinned fingerprint (root of trust)
2. ARK is self-signed (RSA-PSS SHA-384)
3. ASK is signed by ARK (RSA-PSS SHA-384)  
4. VCEK is signed by ASK (RSA-PSS SHA-384)
5. SNP report is signed by VCEK (ECDSA P-384)

**Files:** `src/attestation/sev.rs`

### Step 2: Sigstore Verification (Code Provenance) ✅

**What it verifies:**
1. DSSE envelope signature (ECDSA P-256 over PAE)
2. Certificate is from GitHub Actions OIDC issuer
3. Certificate repository is `tinfoilsh/confidential-model-router`

**Files:** `src/sigstore.rs`

### Step 3: TLS Certificate Pinning ✅

**What it verifies:**
1. Server certificate SPKI fingerprint matches attested value
2. Standard certificate chain validation (CA signatures, expiry)

**Files:** `src/tls.rs`, `src/client.rs`

---

## Verification Output

```
═══ Step 1: Hardware Attestation ═══
   ✓ ARK public key matches pinned fingerprint (root of trust)
   ✓ ARK self-signature verified (RSA-PSS SHA-384)
   ✓ ASK signature verified against ARK
   ✓ VCEK signature verified against ASK
   ✓ Report signature verified against VCEK (ECDSA P-384)
   Router measurement: c50c5d02b1afc51d23e0a91a4e3c3c8a...

═══ Step 2: Sigstore Verification ═══
   ✓ DSSE signature verified (ECDSA P-256)
   ✓ Certificate issuer: GitHub Actions
   ✓ Certificate repository: tinfoilsh/confidential-model-router
   Source measurement: c50c5d02b1afc51d23e0a91a4e3c3c8a...

═══ Step 3: Consistency Verification ═══
   → Comparing measurements... ✓ MATCH!

╔══════════════════════════════════════════════════════════════╗
║                    ✅ VERIFICATION PASSED                    ║
╚══════════════════════════════════════════════════════════════╝
```

---

## File Structure

```
tinfoil-rs/
├── Cargo.toml
├── README.md
├── IMPLEMENTATION.md
│
├── src/
│   ├── lib.rs
│   ├── error.rs
│   ├── attestation/
│   │   ├── mod.rs          # fetch(), verify_full()
│   │   ├── sev.rs          # AMD SEV-SNP + RSA-PSS chain
│   │   ├── tdx.rs          # Intel TDX (placeholder)
│   │   └── types.rs        # Measurement, VerifiedEnclave
│   ├── sigstore.rs         # DSSE verification, PAE encoding
│   ├── tls.rs              # SPKI fingerprint, pinning
│   ├── client.rs           # SecureClient
│   └── api.rs              # Chat/Embedding types
│
└── examples/
    ├── full_verification.rs  # Complete 3-step demo
    ├── test_api.rs           # API with TLS pinning
    ├── test_pinning.rs       # TLS pinning test
    └── debug_tls.rs          # TLS debugging
```

---

## Test Results

```
running 9 tests
test attestation::sev::tests::test_ark_fingerprint_constant ... ok
test attestation::sev::tests::test_signature_parsing ... ok
test attestation::sev::tests::test_measurement_fingerprint ... ok
test client::tests::test_client_creation ... ok
test client::tests::test_default_client ... ok
test client::tests::test_not_verified_error ... ok
test sigstore::tests::test_pae_encoding ... ok
test tls::tests::test_fingerprint_format ... ok
test sigstore::tests::test_verify_repo_full ... ok

test result: ok. 9 passed; 0 failed
```

---

## Usage for Memory Box

```rust
use tinfoil::{attestation, sigstore, SecureClient, ChatMessage};

// Verify the router enclave
let doc = attestation::fetch("inference.tinfoil.sh").await?;
let enclave = attestation::verify_full(&doc).await?;
let source = sigstore::verify_repo("tinfoilsh/confidential-model-router").await?;
enclave.measurement.equals(&source)?;

// Create verified client
let mut client = SecureClient::new("inference.tinfoil.sh", api_key);
client.verify().await?;

// Generate embeddings (nomic-embed-text)
let embedding = client.embed("my secret memory").await?;

// Chat inference (qwen3-coder-480b)
let response = client.chat_with_model("qwen3-coder-480b", vec![
    ChatMessage::user("Analyze this code...")
], None).await?;

// Document processing (docling) - coming soon
```

---

## Security Guarantees

When verification passes:

1. **Hardware is genuine** - AMD's pinned root key signed the chain
2. **Memory is encrypted** - SEV-SNP hardware encryption
3. **Router code is auditable** - Exact GitHub code running
4. **Build is legitimate** - GitHub Actions certificate
5. **Connection is secure** - TLS pinned to attested cert
6. **Model enclaves verified** - Router performs internal attestation

**Your data flows through verified enclaves at every step.**

---

## Dependencies

All pure Rust, no system dependencies:

- `tokio` - Async runtime
- `reqwest` (rustls) - HTTP client
- `rustls` - TLS implementation  
- `p256`, `p384` - Elliptic curves (ECDSA)
- `rsa` - RSA-PSS verification
- `sha2` - SHA-256/SHA-384 hashing
- `x509-cert`, `der` - Certificate parsing
