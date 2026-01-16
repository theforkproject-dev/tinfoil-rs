//! Core types for attestation verification

use serde::{Deserialize, Serialize};

/// Predicate types for different attestation formats
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PredicateType {
    #[serde(rename = "https://tinfoil.sh/predicate/sev-snp-guest/v2")]
    SevGuestV2,
    
    #[serde(rename = "https://tinfoil.sh/predicate/tdx-guest/v2")]
    TdxGuestV2,
    
    #[serde(rename = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1")]
    SnpTdxMultiPlatformV1,
    
    #[serde(other)]
    Unknown,
}

/// Raw attestation document from the enclave
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationDocument {
    pub format: PredicateType,
    pub body: String, // Base64-encoded, gzipped attestation
}

/// Measurement registers from the enclave
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measurement {
    pub type_: PredicateType,
    pub registers: Vec<String>,
}

impl Measurement {
    /// Compare measurements, handling multi-platform predicates
    pub fn equals(&self, other: &Measurement) -> Result<(), MeasurementError> {
        // Multi-platform to specific platform comparison
        if self.type_ == PredicateType::SnpTdxMultiPlatformV1 {
            return self.compare_multiplatform(other);
        }
        if other.type_ == PredicateType::SnpTdxMultiPlatformV1 {
            return other.compare_multiplatform(self);
        }
        
        // Direct comparison
        if self.type_ != other.type_ {
            return Err(MeasurementError::FormatMismatch);
        }
        
        if self.registers != other.registers {
            return Err(MeasurementError::RegisterMismatch);
        }
        
        Ok(())
    }
    
    fn compare_multiplatform(&self, other: &Measurement) -> Result<(), MeasurementError> {
        if self.registers.len() < 3 {
            return Err(MeasurementError::TooFewRegisters);
        }
        
        match other.type_ {
            PredicateType::SevGuestV2 => {
                // Multi-platform register[0] is SNP measurement
                let expected_snp = &self.registers[0];
                let actual_snp = other.registers.get(0)
                    .ok_or(MeasurementError::TooFewRegisters)?;
                
                if expected_snp != actual_snp {
                    return Err(MeasurementError::SnpMismatch);
                }
            }
            PredicateType::TdxGuestV2 => {
                if other.registers.len() < 5 {
                    return Err(MeasurementError::TooFewRegisters);
                }
                
                // Multi-platform registers[1,2] are RTMR1, RTMR2
                // TDX registers are [MRTD, RTMR0, RTMR1, RTMR2, RTMR3]
                let expected_rtmr1 = &self.registers[1];
                let expected_rtmr2 = &self.registers[2];
                let actual_rtmr1 = &other.registers[2];
                let actual_rtmr2 = &other.registers[3];
                
                if expected_rtmr1 != actual_rtmr1 {
                    return Err(MeasurementError::Rtmr1Mismatch);
                }
                if expected_rtmr2 != actual_rtmr2 {
                    return Err(MeasurementError::Rtmr2Mismatch);
                }
                
                // RTMR3 should be zeros
                let rtmr3_zero = "0".repeat(96);
                if other.registers[4] != rtmr3_zero {
                    return Err(MeasurementError::Rtmr3Mismatch);
                }
            }
            _ => return Err(MeasurementError::FormatMismatch),
        }
        
        Ok(())
    }
    
    /// Compute fingerprint of measurement
    pub fn fingerprint(&self) -> String {
        use sha2::{Sha256, Digest};
        
        let joined = self.registers.join("|");
        let hash = Sha256::digest(joined.as_bytes());
        hex::encode(hash)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum MeasurementError {
    #[error("Attestation format mismatch")]
    FormatMismatch,
    
    #[error("Register values don't match")]
    RegisterMismatch,
    
    #[error("Too few registers in measurement")]
    TooFewRegisters,
    
    #[error("SNP measurement mismatch")]
    SnpMismatch,
    
    #[error("RTMR1 mismatch")]
    Rtmr1Mismatch,
    
    #[error("RTMR2 mismatch")]
    Rtmr2Mismatch,
    
    #[error("RTMR3 mismatch (expected zeros)")]
    Rtmr3Mismatch,
}

/// Result of successful attestation verification
#[derive(Debug, Clone)]
pub struct Verification {
    /// Enclave measurement registers
    pub measurement: Measurement,
    
    /// TLS public key fingerprint (hex-encoded SHA256)
    pub tls_public_key_fp: String,
    
    /// HPKE public key for encrypted communication (hex-encoded)
    pub hpke_public_key: Option<String>,
}

/// Ground truth after full verification
#[derive(Debug, Clone)]
pub struct GroundTruth {
    /// TLS certificate fingerprint to pin
    pub tls_public_key: String,
    
    /// HPKE public key for EHBP (optional)
    pub hpke_public_key: Option<String>,
    
    /// Expected measurement (from config or Sigstore)
    pub expected_measurement: Measurement,
    
    /// Actual measurement (from enclave)
    pub enclave_measurement: Measurement,
}
