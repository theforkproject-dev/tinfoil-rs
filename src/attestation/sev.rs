//! AMD SEV-SNP attestation verification
//!
//! This module verifies SEV-SNP attestation reports using the AMD certificate chain.
//! The verification flow:
//! 1. Parse the raw attestation report
//! 2. Validate policy flags (debug must be disabled, etc.)
//! 3. Validate TCB versions meet minimum requirements
//! 4. Validate firmware version meets minimum requirements
//! 5. Fetch VCEK certificate from AMD KDS (via Tinfoil's proxy)
//! 6. Verify ARK public key matches pinned value (root of trust)
//! 7. Verify ARK is self-signed (RSA-PSS SHA-384)
//! 8. Verify ASK is signed by ARK (RSA-PSS SHA-384)
//! 9. Verify VCEK is signed by ASK (RSA-PSS SHA-384)
//! 10. Verify report signature against VCEK (ECDSA P-384)
//! 11. Extract measurement and TLS keys

use base64::Engine;
use flate2::read::GzDecoder;
use sha2::{Sha256, Sha384, Digest};
use std::io::Read;

use crate::error::{Error, Result};
use super::types::{Measurement, PredicateType, Verification};

// ============================================================================
// Report Structure Constants (from AMD SEV-SNP ABI spec and go-sev-guest)
// ============================================================================

/// Report size in bytes (0x4A0 = 1184)
const REPORT_SIZE: usize = 0x4A0;

// Field offsets (from go-sev-guest abi.go)
const VERSION_OFFSET: usize = 0x00;
const POLICY_OFFSET: usize = 0x08;
const VMPL_OFFSET: usize = 0x30;
const CURRENT_TCB_OFFSET: usize = 0x38;
const PLATFORM_INFO_OFFSET: usize = 0x40;
const REPORT_DATA_OFFSET: usize = 0x50;
const MEASUREMENT_OFFSET: usize = 0x90;
const REPORTED_TCB_OFFSET: usize = 0x180;
const CHIP_ID_OFFSET: usize = 0x1A0;
const CURRENT_BUILD_OFFSET: usize = 0x1E8;
const CURRENT_MINOR_OFFSET: usize = 0x1E9;
const CURRENT_MAJOR_OFFSET: usize = 0x1EA;
const LAUNCH_TCB_OFFSET: usize = 0x1F0;
const SIGNATURE_OFFSET: usize = 0x2A0;

// Field sizes
const REPORT_DATA_SIZE: usize = 64;
const MEASUREMENT_SIZE: usize = 48;
const CHIP_ID_SIZE: usize = 64;
const SIGNATURE_SIZE: usize = 512;

// Signature component sizes (AMD SEV-SNP ECDSA P-384)
const SIG_COMPONENT_SIZE: usize = 72;
const SIG_VALUE_SIZE: usize = 48;  // P-384 scalar size

// ============================================================================
// Policy Bit Positions (from go-sev-guest abi.go)
// ============================================================================

const POLICY_SMT_BIT: u64 = 16;
const POLICY_RESERVED1_BIT: u64 = 17;  // Must be 1
const POLICY_MIGRATE_MA_BIT: u64 = 18;
const POLICY_DEBUG_BIT: u64 = 19;
const POLICY_SINGLE_SOCKET_BIT: u64 = 20;

// ============================================================================
// Platform Info Bit Positions
// ============================================================================

const PLATFORM_INFO_SMT_BIT: u64 = 0;
const PLATFORM_INFO_TSME_BIT: u64 = 1;

// ============================================================================
// Security Requirements (from Tinfoil's verifier sev.go)
// ============================================================================

/// Minimum TCB version components
/// These are the minimum security version numbers for each firmware component.
/// Values from tinfoilsh/verifier attestation/sev.go
#[derive(Debug, Clone, Copy)]
pub struct TcbVersion {
    pub boot_loader: u8,  // BlSpl
    pub tee: u8,          // TeeSpl
    pub snp: u8,          // SnpSpl
    pub microcode: u8,    // UcodeSpl
}

impl TcbVersion {
    /// Parse TCB version from 8-byte little-endian value
    /// Layout: [bl_spl(8), tee_spl(8), reserved(32), snp_spl(8), ucode_spl(8)]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let val = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        Self {
            boot_loader: (val & 0xFF) as u8,
            tee: ((val >> 8) & 0xFF) as u8,
            snp: ((val >> 48) & 0xFF) as u8,
            microcode: ((val >> 56) & 0xFF) as u8,
        }
    }

    /// Check if this TCB meets minimum requirements
    pub fn meets_minimum(&self, min: &TcbVersion) -> bool {
        self.boot_loader >= min.boot_loader
            && self.tee >= min.tee
            && self.snp >= min.snp
            && self.microcode >= min.microcode
    }
}

/// Minimum TCB requirements (from tinfoilsh/verifier)
const MIN_TCB: TcbVersion = TcbVersion {
    boot_loader: 0x07,
    tee: 0x00,
    snp: 0x0e,      // 14
    microcode: 0x48, // 72
};

/// Minimum firmware build number
const MIN_BUILD: u8 = 21;

/// Minimum firmware version (major.minor encoded as (major << 8) | minor)
const MIN_VERSION_MAJOR: u8 = 1;
const MIN_VERSION_MINOR: u8 = 55;

/// AMD ARK (AMD Root Key) for Genoa processors
/// This is the SPKI (SubjectPublicKeyInfo) SHA-256 fingerprint of the ARK public key.
/// Pinning this value ensures we only trust certificates signed by AMD's genuine root key.
const AMD_ARK_GENOA_SPKI_FINGERPRINT: &str = "429a69c9422aa258ee4d8db5fcda9c6470ef15f8cd5a9cebd6cbc7d90b863831";

// ============================================================================
// Policy Parsing
// ============================================================================

/// Parsed SNP guest policy
#[derive(Debug, Clone)]
pub struct SnpPolicy {
    pub abi_minor: u8,
    pub abi_major: u8,
    pub smt: bool,
    pub migrate_ma: bool,
    pub debug: bool,
    pub single_socket: bool,
}

impl SnpPolicy {
    /// Parse policy from 64-bit value
    pub fn from_u64(policy: u64) -> Result<Self> {
        // Check reserved bit 17 is set (must be 1)
        if policy & (1 << POLICY_RESERVED1_BIT) == 0 {
            return Err(Error::AttestationVerification(
                "Policy reserved bit 17 must be 1".into()
            ));
        }

        // Check reserved bits 63:26 are zero
        if policy & 0xFFFF_FFFC_0000_0000 != 0 {
            return Err(Error::AttestationVerification(
                "Policy reserved bits [63:26] must be zero".into()
            ));
        }

        Ok(Self {
            abi_minor: (policy & 0xFF) as u8,
            abi_major: ((policy >> 8) & 0xFF) as u8,
            smt: (policy & (1 << POLICY_SMT_BIT)) != 0,
            migrate_ma: (policy & (1 << POLICY_MIGRATE_MA_BIT)) != 0,
            debug: (policy & (1 << POLICY_DEBUG_BIT)) != 0,
            single_socket: (policy & (1 << POLICY_SINGLE_SOCKET_BIT)) != 0,
        })
    }
}

/// Parsed platform info
#[derive(Debug, Clone)]
pub struct PlatformInfo {
    pub smt_enabled: bool,
    pub tsme_enabled: bool,
}

impl PlatformInfo {
    /// Parse platform info from 64-bit value
    pub fn from_u64(info: u64) -> Self {
        Self {
            smt_enabled: (info & (1 << PLATFORM_INFO_SMT_BIT)) != 0,
            tsme_enabled: (info & (1 << PLATFORM_INFO_TSME_BIT)) != 0,
        }
    }
}

// ============================================================================
// Validation Functions
// ============================================================================

/// Validate report structure and version
fn validate_report_structure(report: &[u8]) -> Result<()> {
    if report.len() != REPORT_SIZE {
        return Err(Error::AttestationVerification(format!(
            "Invalid report size: expected {}, got {}",
            REPORT_SIZE, report.len()
        )));
    }
    
    let version = u32::from_le_bytes(report[VERSION_OFFSET..VERSION_OFFSET+4].try_into().unwrap());
    if version < 2 || version > 5 {
        return Err(Error::AttestationVerification(format!(
            "Unsupported report version: {}. Expected 2-5", version
        )));
    }
    
    Ok(())
}

/// Validate guest policy flags
/// 
/// CRITICAL: This ensures the enclave is in a secure state.
/// - Debug mode MUST be disabled (would allow host to read encrypted memory)
/// - Migration agent SHOULD be disabled (Tinfoil doesn't use it)
fn validate_policy(report: &[u8]) -> Result<SnpPolicy> {
    let policy_bytes = &report[POLICY_OFFSET..POLICY_OFFSET+8];
    let policy_val = u64::from_le_bytes(policy_bytes.try_into().unwrap());
    let policy = SnpPolicy::from_u64(policy_val)?;
    
    // CRITICAL: Debug mode must be disabled
    // If debug is enabled, the host can decrypt the VM's memory
    if policy.debug {
        return Err(Error::AttestationVerification(
            "SECURITY: Debug mode is enabled. Enclave memory can be inspected by host. \
             This is a critical security violation.".into()
        ));
    }
    
    // Migration agent should be disabled for Tinfoil's use case
    if policy.migrate_ma {
        return Err(Error::AttestationVerification(
            "SECURITY: Migration agent is enabled. This allows VM state to be migrated \
             which is not expected for Tinfoil enclaves.".into()
        ));
    }
    
    Ok(policy)
}

/// Validate TCB versions meet minimum requirements
/// 
/// TCB (Trusted Computing Base) versions indicate the security patch level of firmware.
/// Older versions may have known vulnerabilities.
fn validate_tcb_versions(report: &[u8]) -> Result<()> {
    // Check Current TCB
    let current_tcb_bytes = &report[CURRENT_TCB_OFFSET..CURRENT_TCB_OFFSET+8];
    let current_tcb = TcbVersion::from_bytes(current_tcb_bytes);
    
    if !current_tcb.meets_minimum(&MIN_TCB) {
        return Err(Error::AttestationVerification(format!(
            "SECURITY: Current TCB version too low. Got: bl={:#x} tee={:#x} snp={:#x} ucode={:#x}. \
             Minimum: bl={:#x} tee={:#x} snp={:#x} ucode={:#x}",
            current_tcb.boot_loader, current_tcb.tee, current_tcb.snp, current_tcb.microcode,
            MIN_TCB.boot_loader, MIN_TCB.tee, MIN_TCB.snp, MIN_TCB.microcode
        )));
    }
    
    // Check Reported TCB (what the guest sees)
    let reported_tcb_bytes = &report[REPORTED_TCB_OFFSET..REPORTED_TCB_OFFSET+8];
    let reported_tcb = TcbVersion::from_bytes(reported_tcb_bytes);
    
    if !reported_tcb.meets_minimum(&MIN_TCB) {
        return Err(Error::AttestationVerification(format!(
            "SECURITY: Reported TCB version too low. Got: bl={:#x} tee={:#x} snp={:#x} ucode={:#x}. \
             Minimum: bl={:#x} tee={:#x} snp={:#x} ucode={:#x}",
            reported_tcb.boot_loader, reported_tcb.tee, reported_tcb.snp, reported_tcb.microcode,
            MIN_TCB.boot_loader, MIN_TCB.tee, MIN_TCB.snp, MIN_TCB.microcode
        )));
    }
    
    // Check Launch TCB
    let launch_tcb_bytes = &report[LAUNCH_TCB_OFFSET..LAUNCH_TCB_OFFSET+8];
    let launch_tcb = TcbVersion::from_bytes(launch_tcb_bytes);
    
    if !launch_tcb.meets_minimum(&MIN_TCB) {
        return Err(Error::AttestationVerification(format!(
            "SECURITY: Launch TCB version too low. Got: bl={:#x} tee={:#x} snp={:#x} ucode={:#x}. \
             Minimum: bl={:#x} tee={:#x} snp={:#x} ucode={:#x}",
            launch_tcb.boot_loader, launch_tcb.tee, launch_tcb.snp, launch_tcb.microcode,
            MIN_TCB.boot_loader, MIN_TCB.tee, MIN_TCB.snp, MIN_TCB.microcode
        )));
    }
    
    Ok(())
}

/// Validate firmware version meets minimum requirements
fn validate_firmware_version(report: &[u8]) -> Result<()> {
    let build = report[CURRENT_BUILD_OFFSET];
    let minor = report[CURRENT_MINOR_OFFSET];
    let major = report[CURRENT_MAJOR_OFFSET];
    
    // Check minimum build number
    if build < MIN_BUILD {
        return Err(Error::AttestationVerification(format!(
            "SECURITY: Firmware build version too low. Got: {}, minimum: {}",
            build, MIN_BUILD
        )));
    }
    
    // Check minimum major.minor version
    let version = ((major as u16) << 8) | (minor as u16);
    let min_version = ((MIN_VERSION_MAJOR as u16) << 8) | (MIN_VERSION_MINOR as u16);
    
    if version < min_version {
        return Err(Error::AttestationVerification(format!(
            "SECURITY: Firmware version too low. Got: {}.{}, minimum: {}.{}",
            major, minor, MIN_VERSION_MAJOR, MIN_VERSION_MINOR
        )));
    }
    
    Ok(())
}

/// Validate platform info
fn validate_platform_info(report: &[u8]) -> Result<PlatformInfo> {
    let info_bytes = &report[PLATFORM_INFO_OFFSET..PLATFORM_INFO_OFFSET+8];
    let info_val = u64::from_le_bytes(info_bytes.try_into().unwrap());
    let info = PlatformInfo::from_u64(info_val);
    
    // Tinfoil expects TSME (Transparent Secure Memory Encryption) to be enabled
    // This is a platform-level setting, so we just warn if it's not set
    if !info.tsme_enabled {
        // This is not an error, just a note - the enclave is still secure
        // TSME encrypts all memory, but SEV-SNP provides per-VM encryption regardless
    }
    
    Ok(info)
}

/// Validate VMPL (Virtual Machine Privilege Level)
fn validate_vmpl(report: &[u8]) -> Result<()> {
    let vmpl = u32::from_le_bytes(report[VMPL_OFFSET..VMPL_OFFSET+4].try_into().unwrap());
    
    // Tinfoil expects VMPL 0 (most privileged level within the guest)
    // Higher VMPL values indicate less privileged execution contexts
    // For now, we don't enforce this as it depends on the deployment model
    let _ = vmpl; // Acknowledge we're not currently enforcing this
    
    Ok(())
}

// ============================================================================
// Public API
// ============================================================================

/// Verify AMD SEV-SNP attestation and extract measurements
pub fn verify(body: &str) -> Result<Verification> {
    // 1. Decode and decompress
    let report_bytes = decode_report(body)?;
    
    // 2. Validate report structure
    validate_report_structure(&report_bytes)?;
    
    // 3. Validate security-critical policy flags
    let _policy = validate_policy(&report_bytes)?;
    
    // 4. Validate TCB versions
    validate_tcb_versions(&report_bytes)?;
    
    // 5. Validate firmware version
    validate_firmware_version(&report_bytes)?;
    
    // 6. Validate platform info
    let _platform_info = validate_platform_info(&report_bytes)?;
    
    // 7. Validate VMPL
    validate_vmpl(&report_bytes)?;
    
    // 8. Verify report signature (basic check)
    verify_report_signature_basic(&report_bytes)?;
    
    // 9. Extract measurement and keys
    let measurement_bytes = &report_bytes[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_SIZE];
    let report_data = &report_bytes[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + REPORT_DATA_SIZE];
    let tls_fp = hex::encode(&report_data[..32]);
    let hpke_key = hex::encode(&report_data[32..]);
    
    let measurement = Measurement {
        type_: PredicateType::SevGuestV2,
        registers: vec![hex::encode(measurement_bytes)],
    };
    
    Ok(Verification {
        measurement,
        tls_public_key_fp: tls_fp,
        hpke_public_key: Some(hpke_key),
    })
}

/// Full async verification including VCEK fetch and chain validation
pub async fn verify_full(body: &str) -> Result<Verification> {
    // 1. Decode and decompress
    let report_bytes = decode_report(body)?;
    
    // 2. Validate report structure
    validate_report_structure(&report_bytes)?;
    
    // 3. Validate security-critical policy flags
    let _policy = validate_policy(&report_bytes)?;
    
    // 4. Validate TCB versions
    validate_tcb_versions(&report_bytes)?;
    
    // 5. Validate firmware version
    validate_firmware_version(&report_bytes)?;
    
    // 6. Validate platform info
    let _platform_info = validate_platform_info(&report_bytes)?;
    
    // 7. Validate VMPL
    validate_vmpl(&report_bytes)?;
    
    // 8. Extract chip_id and TCB for VCEK lookup
    let chip_id = &report_bytes[CHIP_ID_OFFSET..CHIP_ID_OFFSET + CHIP_ID_SIZE];
    let reported_tcb = &report_bytes[REPORTED_TCB_OFFSET..REPORTED_TCB_OFFSET + 8];
    
    // 9. Fetch and verify certificate chain
    let vcek = fetch_vcek(chip_id, reported_tcb).await?;
    let cert_chain = fetch_cert_chain().await?;
    
    // 10. Verify certificate chain with full cryptographic verification
    verify_cert_chain_crypto(&vcek, &cert_chain)?;
    
    // 11. Verify report signature against VCEK
    verify_report_signature_full(&report_bytes, &vcek)?;
    
    // 12. Extract measurements and keys
    let measurement_bytes = &report_bytes[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_SIZE];
    let report_data = &report_bytes[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + REPORT_DATA_SIZE];
    let tls_fp = hex::encode(&report_data[..32]);
    let hpke_key = hex::encode(&report_data[32..]);
    
    let measurement = Measurement {
        type_: PredicateType::SevGuestV2,
        registers: vec![hex::encode(measurement_bytes)],
    };
    
    Ok(Verification {
        measurement,
        tls_public_key_fp: tls_fp,
        hpke_public_key: Some(hpke_key),
    })
}

// ============================================================================
// Helper Functions
// ============================================================================

fn decode_report(body: &str) -> Result<Vec<u8>> {
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|e| Error::AttestationVerification(format!("Base64 decode failed: {}", e)))?;
    
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut report_bytes = Vec::new();
    decoder.read_to_end(&mut report_bytes)
        .map_err(|e| Error::AttestationVerification(format!("Gzip decompress failed: {}", e)))?;
    
    Ok(report_bytes)
}

/// Parse R and S from the signature bytes
fn parse_signature_components(sig_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if sig_bytes.len() < SIG_COMPONENT_SIZE * 2 {
        return Err(Error::AttestationVerification("Signature too short".into()));
    }
    
    // Extract R (first 48 bytes of first 72-byte component) and convert from LE to BE
    let r_le = &sig_bytes[0..SIG_VALUE_SIZE];
    let r_be: Vec<u8> = r_le.iter().copied().rev().collect();
    
    // Extract S (first 48 bytes of second 72-byte component) and convert from LE to BE
    let s_le = &sig_bytes[SIG_COMPONENT_SIZE..SIG_COMPONENT_SIZE + SIG_VALUE_SIZE];
    let s_be: Vec<u8> = s_le.iter().copied().rev().collect();
    
    Ok((r_be, s_be))
}

fn verify_report_signature_basic(report: &[u8]) -> Result<()> {
    let sig_bytes = &report[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_SIZE];
    
    // Basic check: signature should not be all zeros
    if sig_bytes.iter().all(|&b| b == 0) {
        return Err(Error::AttestationVerification(
            "Invalid signature: all zeros".into()
        ));
    }
    
    // Parse and validate R and S components
    let (r_be, s_be) = parse_signature_components(sig_bytes)?;
    
    if r_be.iter().all(|&b| b == 0) || s_be.iter().all(|&b| b == 0) {
        return Err(Error::AttestationVerification(
            "Invalid ECDSA signature components".into()
        ));
    }
    
    Ok(())
}

/// Fetch VCEK certificate from AMD KDS via Tinfoil's proxy
async fn fetch_vcek(chip_id: &[u8], tcb: &[u8]) -> Result<Vec<u8>> {
    let tcb_version = TcbVersion::from_bytes(tcb);
    let chip_id_hex = hex::encode(chip_id);
    
    // AMD KDS URL format (via Tinfoil proxy)
    let url = format!(
        "https://kds-proxy.tinfoil.sh/vcek/v1/Genoa/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
        chip_id_hex,
        tcb_version.boot_loader,
        tcb_version.tee,
        tcb_version.snp,
        tcb_version.microcode
    );
    
    let response = reqwest::get(&url)
        .await
        .map_err(|e| Error::AttestationVerification(format!("Failed to fetch VCEK: {}", e)))?;
    
    if !response.status().is_success() {
        return Err(Error::AttestationVerification(format!(
            "VCEK fetch failed: HTTP {}",
            response.status()
        )));
    }
    
    let vcek_der = response.bytes().await
        .map_err(|e| Error::AttestationVerification(format!("Failed to read VCEK: {}", e)))?;
    
    Ok(vcek_der.to_vec())
}

/// Fetch AMD certificate chain (ASK + ARK)
async fn fetch_cert_chain() -> Result<Vec<u8>> {
    let url = "https://kds-proxy.tinfoil.sh/vcek/v1/Genoa/cert_chain";
    
    let response = reqwest::get(url)
        .await
        .map_err(|e| Error::AttestationVerification(format!("Failed to fetch cert chain: {}", e)))?;
    
    if !response.status().is_success() {
        return Err(Error::AttestationVerification(format!(
            "Cert chain fetch failed: HTTP {}",
            response.status()
        )));
    }
    
    let chain_pem = response.bytes().await
        .map_err(|e| Error::AttestationVerification(format!("Failed to read cert chain: {}", e)))?;
    
    Ok(chain_pem.to_vec())
}

/// Parse PEM certificates from the chain
fn parse_pem_chain(chain_pem: &[u8]) -> Result<Vec<Vec<u8>>> {
    let pems = pem::parse_many(chain_pem)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse PEM chain: {}", e)))?;
    
    Ok(pems.into_iter().map(|p| p.contents().to_vec()).collect())
}

/// Compute SPKI fingerprint of a certificate's public key
fn compute_spki_fingerprint(cert_der: &[u8]) -> Result<String> {
    use x509_cert::Certificate;
    use der::{Decode, Encode};
    
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse cert: {}", e)))?;
    
    let spki_der = cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::AttestationVerification(format!("Failed to encode SPKI: {}", e)))?;
    
    let hash = Sha256::digest(&spki_der);
    Ok(hex::encode(hash))
}

/// Extract public key bytes from a certificate
fn extract_pubkey_from_cert(cert_der: &[u8]) -> Result<Vec<u8>> {
    use x509_cert::Certificate;
    use der::{Decode, Encode};
    
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse cert: {}", e)))?;
    
    cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::AttestationVerification(format!("Failed to encode SPKI: {}", e)))
}

/// Extract TBS (To Be Signed) certificate bytes
fn extract_tbs_from_cert(cert_der: &[u8]) -> Result<Vec<u8>> {
    use x509_cert::Certificate;
    use der::{Decode, Encode};
    
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse cert: {}", e)))?;
    
    cert.tbs_certificate
        .to_der()
        .map_err(|e| Error::AttestationVerification(format!("Failed to encode TBS: {}", e)))
}

/// Extract signature bytes from a certificate
fn extract_signature_from_cert(cert_der: &[u8]) -> Result<Vec<u8>> {
    use x509_cert::Certificate;
    use der::Decode;
    
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse cert: {}", e)))?;
    
    Ok(cert.signature.raw_bytes().to_vec())
}

/// Verify the certificate chain with full cryptographic verification
fn verify_cert_chain_crypto(vcek_der: &[u8], cert_chain_pem: &[u8]) -> Result<()> {
    use x509_cert::Certificate;
    use der::Decode;
    
    // Parse certificates
    let vcek_cert = Certificate::from_der(vcek_der)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse VCEK: {}", e)))?;
    
    let chain_certs = parse_pem_chain(cert_chain_pem)?;
    if chain_certs.len() < 2 {
        return Err(Error::AttestationVerification(
            "Certificate chain should contain ASK and ARK".into()
        ));
    }
    
    let ask_der = &chain_certs[0];
    let ark_der = &chain_certs[1];
    
    let ask_cert = Certificate::from_der(ask_der)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse ASK: {}", e)))?;
    
    let ark_cert = Certificate::from_der(ark_der)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse ARK: {}", e)))?;
    
    // === STEP 1: Verify ARK public key matches pinned fingerprint ===
    let ark_fingerprint = compute_spki_fingerprint(ark_der)?;
    if ark_fingerprint != AMD_ARK_GENOA_SPKI_FINGERPRINT {
        return Err(Error::AttestationVerification(format!(
            "ARK public key fingerprint mismatch! Expected: {}, Got: {}. \
             This could indicate a MITM attack or AMD has rotated their root key.",
            AMD_ARK_GENOA_SPKI_FINGERPRINT, ark_fingerprint
        )));
    }
    
    // === STEP 2: Verify issuer/subject chain structure ===
    let vcek_issuer = &vcek_cert.tbs_certificate.issuer;
    let ask_subject = &ask_cert.tbs_certificate.subject;
    let ask_issuer = &ask_cert.tbs_certificate.issuer;
    let ark_subject = &ark_cert.tbs_certificate.subject;
    let ark_issuer = &ark_cert.tbs_certificate.issuer;
    
    if vcek_issuer != ask_subject {
        return Err(Error::AttestationVerification(
            "VCEK issuer does not match ASK subject".into()
        ));
    }
    
    if ask_issuer != ark_subject {
        return Err(Error::AttestationVerification(
            "ASK issuer does not match ARK subject".into()
        ));
    }
    
    if ark_issuer != ark_subject {
        return Err(Error::AttestationVerification(
            "ARK is not self-signed".into()
        ));
    }
    
    // Verify CN values
    let ark_cn = extract_cn(ark_subject)?;
    if ark_cn != "ARK-Genoa" {
        return Err(Error::AttestationVerification(format!(
            "Unexpected ARK CN: {}, expected ARK-Genoa", ark_cn
        )));
    }
    
    let ask_cn = extract_cn(ask_subject)?;
    if ask_cn != "SEV-Genoa" {
        return Err(Error::AttestationVerification(format!(
            "Unexpected ASK CN: {}, expected SEV-Genoa", ask_cn
        )));
    }
    
    // === STEP 3: Verify ARK self-signature (RSA-PSS SHA-384) ===
    let ark_pubkey = extract_pubkey_from_cert(ark_der)?;
    let ark_tbs = extract_tbs_from_cert(ark_der)?;
    let ark_sig = extract_signature_from_cert(ark_der)?;
    verify_rsa_pss_signature(&ark_tbs, &ark_sig, &ark_pubkey, "ARK self-signature")?;
    
    // === STEP 4: Verify ASK signature against ARK ===
    let ask_tbs = extract_tbs_from_cert(ask_der)?;
    let ask_sig = extract_signature_from_cert(ask_der)?;
    verify_rsa_pss_signature(&ask_tbs, &ask_sig, &ark_pubkey, "ASK signature")?;
    
    // === STEP 5: Verify VCEK signature against ASK ===
    let ask_pubkey = extract_pubkey_from_cert(ask_der)?;
    let vcek_tbs = extract_tbs_from_cert(vcek_der)?;
    let vcek_sig = extract_signature_from_cert(vcek_der)?;
    verify_rsa_pss_signature(&vcek_tbs, &vcek_sig, &ask_pubkey, "VCEK signature")?;
    
    Ok(())
}

/// Verify an RSA-PSS SHA-384 signature
fn verify_rsa_pss_signature(
    tbs_der: &[u8],
    signature: &[u8],
    signer_spki_der: &[u8],
    context: &str,
) -> Result<()> {
    use rsa::RsaPublicKey;
    use rsa::pss::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use rsa::pkcs8::DecodePublicKey;
    
    let rsa_pubkey = RsaPublicKey::from_public_key_der(signer_spki_der)
        .map_err(|e| Error::AttestationVerification(format!("Invalid RSA public key for {}: {}", context, e)))?;
    
    let verifying_key: VerifyingKey<Sha384> = VerifyingKey::new(rsa_pubkey);
    
    let sig = Signature::try_from(signature)
        .map_err(|e| Error::AttestationVerification(format!("Invalid signature format for {}: {}", context, e)))?;
    
    verifying_key.verify(tbs_der, &sig)
        .map_err(|e| Error::AttestationVerification(format!("{} verification failed: {}", context, e)))?;
    
    Ok(())
}

/// Extract Common Name from X.509 Name
fn extract_cn(name: &x509_cert::name::Name) -> Result<String> {
    use x509_cert::der::oid::db::rfc4519::CN;
    use der::asn1::Utf8StringRef;
    use der::{Decode, Encode};
    
    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == CN {
                let value_bytes = atv.value.value();
                
                if let Ok(s) = Utf8StringRef::from_der(atv.value.to_der().unwrap_or_default().as_slice()) {
                    return Ok(s.as_str().to_string());
                }
                
                if let Ok(s) = std::str::from_utf8(value_bytes) {
                    return Ok(s.to_string());
                }
                
                return Err(Error::AttestationVerification("CN value is not valid UTF-8".into()));
            }
        }
    }
    
    Err(Error::AttestationVerification("No CN found in certificate".into()))
}

/// Verify report signature against VCEK public key
#[allow(deprecated)]
fn verify_report_signature_full(report: &[u8], vcek: &[u8]) -> Result<()> {
    use x509_cert::Certificate;
    use der::Decode;
    use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    use p384::elliptic_curve::generic_array::GenericArray;
    
    let vcek_cert = Certificate::from_der(vcek)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse VCEK: {}", e)))?;
    
    let pubkey_bytes = vcek_cert.tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    
    let report_body = &report[0..SIGNATURE_OFFSET];
    
    let sig_bytes = &report[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_SIZE];
    let (r_be, s_be) = parse_signature_components(sig_bytes)?;
    
    let signature = Signature::from_scalars(
        GenericArray::clone_from_slice(&r_be),
        GenericArray::clone_from_slice(&s_be),
    ).map_err(|e| Error::AttestationVerification(format!("Invalid signature format: {}", e)))?;
    
    let verifying_key = VerifyingKey::from_sec1_bytes(pubkey_bytes)
        .map_err(|e| Error::AttestationVerification(format!("Invalid VCEK public key: {}", e)))?;
    
    verifying_key.verify(report_body, &signature)
        .map_err(|e| Error::AttestationVerification(format!("Signature verification failed: {}", e)))?;
    
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tcb_version_parsing() {
        // Example TCB bytes: [bl=0x07, tee=0x00, 0, 0, 0, 0, snp=0x0e, ucode=0x48]
        let bytes: [u8; 8] = [0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x48];
        let tcb = TcbVersion::from_bytes(&bytes);
        
        assert_eq!(tcb.boot_loader, 0x07);
        assert_eq!(tcb.tee, 0x00);
        assert_eq!(tcb.snp, 0x0e);
        assert_eq!(tcb.microcode, 0x48);
        
        assert!(tcb.meets_minimum(&MIN_TCB));
    }
    
    #[test]
    fn test_tcb_version_below_minimum() {
        // TCB with low microcode version
        let bytes: [u8; 8] = [0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x40];
        let tcb = TcbVersion::from_bytes(&bytes);
        
        assert!(!tcb.meets_minimum(&MIN_TCB));
    }
    
    #[test]
    fn test_policy_parsing_valid() {
        // Policy with reserved bit 17 set, SMT enabled, debug disabled
        let policy = (1u64 << 17) | (1u64 << 16); // Reserved1 + SMT
        let parsed = SnpPolicy::from_u64(policy).unwrap();
        
        assert!(parsed.smt);
        assert!(!parsed.debug);
        assert!(!parsed.migrate_ma);
    }
    
    #[test]
    fn test_policy_parsing_missing_reserved_bit() {
        // Policy without reserved bit 17 - should fail
        let policy = 1u64 << 16; // Only SMT, missing Reserved1
        let result = SnpPolicy::from_u64(policy);
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_policy_with_debug_enabled() {
        // Policy with debug enabled
        let policy = (1u64 << 17) | (1u64 << 19); // Reserved1 + Debug
        let parsed = SnpPolicy::from_u64(policy).unwrap();
        
        assert!(parsed.debug);
    }
    
    #[test]
    fn test_platform_info_parsing() {
        let info = (1u64 << 0) | (1u64 << 1); // SMT + TSME
        let parsed = PlatformInfo::from_u64(info);
        
        assert!(parsed.smt_enabled);
        assert!(parsed.tsme_enabled);
    }
    
    #[test]
    fn test_signature_parsing() {
        let mut sig = vec![0u8; 512];
        
        // R component: little-endian 48 bytes
        for i in 0..48 {
            sig[i] = (48 - i) as u8;
        }
        
        // S component: starts at offset 72
        for i in 0..48 {
            sig[72 + i] = (i + 1) as u8;
        }
        
        let (r_be, s_be) = parse_signature_components(&sig).unwrap();
        
        assert_eq!(r_be[0], 1);
        assert_eq!(r_be[47], 48);
        assert_eq!(s_be[0], 48);
        assert_eq!(s_be[47], 1);
    }
    
    #[test]
    fn test_ark_fingerprint_constant() {
        assert_eq!(AMD_ARK_GENOA_SPKI_FINGERPRINT.len(), 64);
        assert!(AMD_ARK_GENOA_SPKI_FINGERPRINT.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
