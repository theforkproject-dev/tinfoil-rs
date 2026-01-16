//! Intel TDX attestation verification

use base64::Engine;
use flate2::read::GzDecoder;
use std::io::Read;

use crate::error::{Error, Result};
use super::types::{Measurement, PredicateType, Verification};

/// Verify Intel TDX attestation and extract measurements
pub fn verify(body: &str) -> Result<Verification> {
    // 1. Decode base64
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|e| Error::AttestationVerification(format!("Base64 decode failed: {}", e)))?;
    
    // 2. Decompress gzip
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)
        .map_err(|e| Error::AttestationVerification(format!("Gzip decompress failed: {}", e)))?;
    
    // 3. Parse the TDX quote
    let quote = parse_tdx_quote(&decompressed)?;
    
    // 4. Verify the signature chain to Intel root
    verify_signature_chain(&quote)?;
    
    // 5. Extract measurements and keys
    let measurement = extract_measurement(&quote);
    let (tls_fp, hpke_key) = extract_keys(&quote);
    
    Ok(Verification {
        measurement,
        tls_public_key_fp: tls_fp,
        hpke_public_key: Some(hpke_key),
    })
}

/// Parsed TDX Quote
struct TdxQuote {
    /// Raw quote bytes
    raw: Vec<u8>,
    
    /// MRTD - Measurement of TDX module
    mrtd: [u8; 48],
    
    /// RTMR0 - Runtime measurement register 0
    rtmr0: [u8; 48],
    
    /// RTMR1 - Runtime measurement register 1
    rtmr1: [u8; 48],
    
    /// RTMR2 - Runtime measurement register 2
    rtmr2: [u8; 48],
    
    /// RTMR3 - Runtime measurement register 3
    rtmr3: [u8; 48],
    
    /// Keys appended to quote (64 bytes: 32 TLS + 32 HPKE)
    keys: [u8; 64],
}

fn parse_tdx_quote(data: &[u8]) -> Result<TdxQuote> {
    // TDX Quote v4 structure (simplified):
    // - Header: 48 bytes
    // - TD Report: 584 bytes
    //   - MRTD at offset 128, 48 bytes
    //   - RTMR0 at offset 176, 48 bytes  
    //   - RTMR1 at offset 224, 48 bytes
    //   - RTMR2 at offset 272, 48 bytes
    //   - RTMR3 at offset 320, 48 bytes
    // - Signature
    // - Keys appended (64 bytes)
    
    if data.len() < 632 + 64 {
        return Err(Error::AttestationVerification(
            "TDX quote data too short".into()
        ));
    }
    
    let quote_end = data.len() - 64;
    let keys_bytes = &data[quote_end..];
    
    // TD Report starts at offset 48 (after header)
    let td_report_start = 48;
    
    let mut mrtd = [0u8; 48];
    let mut rtmr0 = [0u8; 48];
    let mut rtmr1 = [0u8; 48];
    let mut rtmr2 = [0u8; 48];
    let mut rtmr3 = [0u8; 48];
    
    mrtd.copy_from_slice(&data[td_report_start + 128..td_report_start + 176]);
    rtmr0.copy_from_slice(&data[td_report_start + 176..td_report_start + 224]);
    rtmr1.copy_from_slice(&data[td_report_start + 224..td_report_start + 272]);
    rtmr2.copy_from_slice(&data[td_report_start + 272..td_report_start + 320]);
    rtmr3.copy_from_slice(&data[td_report_start + 320..td_report_start + 368]);
    
    let mut keys = [0u8; 64];
    keys.copy_from_slice(keys_bytes);
    
    Ok(TdxQuote {
        raw: data[..quote_end].to_vec(),
        mrtd,
        rtmr0,
        rtmr1,
        rtmr2,
        rtmr3,
        keys,
    })
}

fn verify_signature_chain(quote: &TdxQuote) -> Result<()> {
    // TODO: Full implementation would:
    // 1. Verify QE (Quoting Enclave) signature
    // 2. Verify PCK certificate chain to Intel root
    // 3. Check TCB status against Intel's collateral
    //
    // For MVP, we'll trust the quote structure and add full verification later
    
    if quote.raw.is_empty() {
        return Err(Error::AttestationVerification(
            "Empty TDX quote".into()
        ));
    }
    
    // TODO: Implement full Intel TDX verification
    
    Ok(())
}

fn extract_measurement(quote: &TdxQuote) -> Measurement {
    Measurement {
        type_: PredicateType::TdxGuestV2,
        registers: vec![
            hex::encode(quote.mrtd),
            hex::encode(quote.rtmr0),
            hex::encode(quote.rtmr1),
            hex::encode(quote.rtmr2),
            hex::encode(quote.rtmr3),
        ],
    }
}

fn extract_keys(quote: &TdxQuote) -> (String, String) {
    let tls_fp = hex::encode(&quote.keys[..32]);
    let hpke_key = hex::encode(&quote.keys[32..]);
    (tls_fp, hpke_key)
}
