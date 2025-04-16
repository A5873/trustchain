//! Verification functionality for TrustChain.
//!
//! This module provides high-level verification operations, including:
//! - Context for configuring verification parameters
//! - Trust chain verification logic
//! - Artifact verification with signatures
//! - Verification policy support

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

use crate::error::{CryptoError, CryptoResult};
use crate::hash::{self, HashAlgorithm, HashFunction};
use crate::key::{KeyInfo, KeyPair, KeyStorage, KeyType, KeyUsage, MemoryKeyStorage};
use crate::signature::{Signature, SignatureAlgorithm, SignatureProvider, Ed25519SignatureProvider};

/// Minimum trust level required for a key to be considered trusted
pub const DEFAULT_MIN_TRUST_LEVEL: u8 = 1;

/// Verification mode for trust chain validation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationMode {
    /// Strict mode requires all signatures and attestations to be valid
    Strict,
    /// Best-effort mode allows some attestations to be missing if there's enough trust
    BestEffort,
    /// Permissive mode allows verification to succeed with warnings
    Permissive,
}

/// Trust level for verification results
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustLevel {
    /// No trust - verification failed
    None,
    /// Low trust - minimal verification passed
    Low,
    /// Medium trust - standard verification passed
    Medium,
    /// High trust - comprehensive verification passed
    High,
    /// Maximum trust - all possible verifications passed
    Maximum,
}

impl TrustLevel {
    /// Convert from a numeric value
    pub fn from_value(value: u8) -> Self {
        match value {
            0 => TrustLevel::None,
            1 => TrustLevel::Low,
            2 => TrustLevel::Medium,
            3 => TrustLevel::High,
            _ => TrustLevel::Maximum,
        }
    }
    
    /// Convert to a numeric value
    pub fn as_value(&self) -> u8 {
        match self {
            TrustLevel::None => 0,
            TrustLevel::Low => 1,
            TrustLevel::Medium => 2,
            TrustLevel::High => 3,
            TrustLevel::Maximum => 4,
        }
    }
}

/// A verification warning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationWarning {
    /// Warning code
    pub code: String,
    
    /// Warning message
    pub message: String,
    
    /// Severity (0-10, higher is more severe)
    pub severity: u8,
}

/// Detailed verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether verification succeeded
    pub is_valid: bool,
    
    /// Trust level of the verification
    pub trust_level: TrustLevel,
    
    /// Optional error message if validation failed
    pub error: Option<String>,
    
    /// Any warnings encountered during verification
    pub warnings: Vec<VerificationWarning>,
    
    /// When the verification was performed (seconds since UNIX epoch)
    pub timestamp: u64,
    
    /// Signatures that were verified
    pub signatures: Vec<Signature>,
    
    /// Key information for keys that were used in verification
    pub keys: Vec<KeyInfo>,
    
    /// Additional metadata about the verification
    pub metadata: HashMap<String, String>,
}

impl VerificationResult {
    /// Create a new successful verification result
    pub fn success(trust_level: TrustLevel) -> Self {
        Self {
            is_valid: true,
            trust_level,
            error: None,
            warnings: Vec::new(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            signatures: Vec::new(),
            keys: Vec::new(),
            metadata: HashMap::new(),
        }
    }
    
    /// Create a new failed verification result
    pub fn failure(error: String) -> Self {
        Self {
            is_valid: false,
            trust_level: TrustLevel::None,
            error: Some(error),
            warnings: Vec::new(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            signatures: Vec::new(),
            keys: Vec::new(),
            metadata: HashMap::new(),
        }
    }
    
    /// Add a warning to the verification result
    pub fn add_warning(&mut self, code: &str, message: &str, severity: u8) {
        self.warnings.push(VerificationWarning {
            code: code.to_string(),
            message: message.to_string(),
            severity,
        });
    }
    
    /// Add a signature to the verification result
    pub fn add_signature(&mut self, signature: Signature) {
        self.signatures.push(signature);
    }
    
    /// Add a key to the verification result
    pub fn add_key(&mut self, key: KeyInfo) {
        self.keys.push(key);
    }
    
    /// Add metadata to the verification result
    pub fn add_metadata(&mut self, key: &str, value: &str) {
        self.metadata.insert(key.to_string(), value.to_string());
    }
    
    /// Check if this result has warnings of at least the given severity
    pub fn has_warnings_with_severity(&self, min_severity: u8) -> bool {
        self.warnings.iter().any(|w| w.severity >= min_severity)
    }
    
    /// Convert to JSON string
    pub fn to_json(&self) -> CryptoResult<String> {
        serde_json::to_string(self).map_err(|e| CryptoError::JsonError(e))
    }
    
    /// Parse from JSON string
    pub fn from_json(json: &str) -> CryptoResult<Self> {
        serde_json::from_str(json).map_err(|e| CryptoError::JsonError(e))
    }
}

/// Trust policy for verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationPolicy {
    /// Name of the policy
    pub name: String,
    
    /// Description of the policy
    pub description: Option<String>,
    
    /// Minimum trust level required for success
    pub min_trust_level: TrustLevel,
    
    /// Verification mode
    pub mode: VerificationMode,
    
    /// Whether expired keys are allowed
    pub allow_expired_keys: bool,
    
    /// Minimum number of signatures required
    pub min_signatures: usize,
    
    /// Minimum number of unique signers required
    pub min_unique_signers: usize,
    
    /// Required signature algorithms
    pub required_algorithms: Option<Vec<SignatureAlgorithm>>,
    
    /// Required key types
    pub required_key_types: Option<Vec<KeyType>>,
    
    /// Whether file hash verification is required
    pub require_hash_verification: bool,
    
    /// Required hash algorithms
    pub required_hash_algorithms: Option<Vec<HashAlgorithm>>,
    
    /// Custom policy rules (key-value pairs)
    pub custom_rules: HashMap<String, String>,
}

impl VerificationPolicy {
    /// Create a new verification policy with default settings
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            description: None,
            min_trust_level: TrustLevel::Medium,
            mode: VerificationMode::Strict,
            allow_expired_keys: false,
            min_signatures: 1,
            min_unique_signers: 1,
            required_algorithms: None,
            required_key_types: None,
            require_hash_verification: true,
            required_hash_algorithms: None,
            custom_rules: HashMap::new(),
        }
    }
    
    /// Create a strict policy requiring multiple signatures
    pub fn strict(name: &str, min_signatures: usize) -> Self {
        Self {
            name: name.to_string(),
            description: Some(format!("Strict policy requiring {} signatures", min_signatures)),
            min_trust_level: TrustLevel::High,
            mode: VerificationMode::Strict,
            allow_expired_keys: false,
            min_signatures,
            min_unique_signers: min_signatures,
            required_algorithms: None,
            required_key_types: None,
            require_hash_verification: true,
            required_hash_algorithms: None,
            custom_rules: HashMap::new(),
        }
    }
    
    /// Create a basic policy with minimal requirements
    pub fn basic(name: &str) -> Self {
        Self {
            name: name.to_string(),
            description: Some("Basic verification policy".to_string()),
            min_trust_level: TrustLevel::Low,
            mode: VerificationMode::BestEffort,
            allow_expired_keys: false,
            min_signatures: 1,
            min_unique_signers: 1,
            required_algorithms: None,
            required_key_types: None,
            require_hash_verification: true,
            required_hash_algorithms: None,
            custom_rules: HashMap::new(),
        }
    }
    
    /// Add a description to the policy
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }
    
    /// Set the minimum trust level
    pub fn with_min_trust_level(mut self, level: TrustLevel) -> Self {
        self.min_trust_level = level;
        self
    }
    
    /// Set the verification mode
    pub fn with_mode(mut self, mode: VerificationMode) -> Self {
        self.mode = mode;
        self
    }
    
    /// Set whether expired keys are allowed
    pub fn allow_expired_keys(mut self, allow: bool) -> Self {
        self.allow_expired_keys = allow;
        self
    }
    
    /// Add a custom rule
    pub fn with_custom_rule(mut self, key: &str, value: &str) -> Self {
        self.custom_rules.insert(key.to_string(), value.to_string());
        self
    }
    
    /// Check if the policy allows a given key
    pub fn allows_key(&self, key: &KeyInfo) -> bool {
        // Check if key is expired
        if !self.allow_expired_keys && key.is_expired() {
            return false;
        }
        
        // Check if key type is allowed
        if let Some(required_types) = &self.required_key_types {
            if !required_types.contains(&key.key_type) {
                return false;
            }
        }
        
        true
    }
    
    /// Check if the policy allows a given signature
    pub fn allows_signature(&self, signature: &Signature) -> bool {
        // Check if algorithm is allowed
        if let Some(required_algorithms) = &self.required_algorithms {
            if !required_algorithms.contains(&signature.algorithm) {
                return false;
            }
        }
        
        true
    }
}

/// Trust chain representing a sequence of signatures and attestations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustChain {
    /// Chain ID
    pub id: String,
    
    /// Subject being attested (file path, package name, etc.)
    pub subject: String,
    
    /// Type of subject
    pub subject_type: String,
    
    /// List of signatures in the chain
    pub signatures: Vec<Signature>,
    
    /// Hash of the subject data
    pub subject_hash: Option<String>,
    
    /// Algorithm used to hash the subject
    pub hash_algorithm: Option<HashAlgorithm>,
    
    /// When the chain was created
    pub created_at: u64,
    
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl TrustChain {
    /// Create a new trust chain
    pub fn new(id: &str, subject: &str, subject_type: &str) -> Self {
        Self {
            id: id.to_string(),
            subject: subject.to_string(),
            subject_type: subject_type.to_string(),
            signatures: Vec::new(),
            subject_hash: None,
            hash_algorithm: None,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            metadata: HashMap::new(),
        }
    }
    
    /// Add a signature to the chain
    pub fn add_signature(&mut self, signature: Signature) {
        self.signatures.push(signature);
    }
    
    /// Add a subject hash
    pub fn with_subject_hash(mut self, hash: &str, algorithm: HashAlgorithm) -> Self {
        self.subject_hash = Some(hash.to_string());
        self.hash_algorithm = Some(algorithm);
        self
    }
    
    /// Add metadata to the chain
    pub fn add_metadata(&mut self, key: &str, value: &str) {
        self.metadata.insert(key.to_string(), value.to_string());
    }
    
    /// Count unique signers in the chain
    pub fn count_unique_signers(&self) -> usize {
        let mut unique_keys = HashSet::new();
        for signature in &self.signatures {
            unique_keys.insert(&signature.key_id);
        }
        unique_keys.len()
    }
    
    /// Convert to JSON string
    pub fn to_json(&self) -> CryptoResult<String> {
        serde_json::to_string(self).map_err(|e| CryptoError::JsonError(e))
    }
    
    /// Parse from JSON string
    pub fn from_json(json: &str) -> CryptoResult<Self> {
        serde_json::from_str(json).map_err(|e| CryptoError::JsonError(e))
    }
}

/// Verification context for configuring and performing verifications
pub struct VerificationContext {
    /// Storage for trusted keys
    key_storage: Box<dyn KeyStorage>,
    
    /// Default verification policy
    default_policy: VerificationPolicy,
    
    /// Named verification policies
    policies: HashMap<String, VerificationPolicy>,
    
    /// Minimum trust level for keys to be considered trusted
    min_key_trust_level: u8,
    
    /// Default hash algorithm
    default_hash_algorithm: HashAlgorithm,
}

impl VerificationContext {
    /// Create a new verification context with in-memory key storage
    pub fn new() -> Self {
        Self {
            key_storage: Box::new(MemoryKeyStorage::new()),
            default_policy: VerificationPolicy::new("default"),
            policies: HashMap::new(),
            min_key_trust_level: DEFAULT_MIN_TRUST_LEVEL,
            default_hash_algorithm: HashAlgorithm::Blake3,
        }
    }
    
    /// Create a new verification context with custom key storage
    pub fn with_storage(storage: Box<dyn KeyStorage>) -> Self {
        Self {
            key_storage: storage,
            default_policy: VerificationPolicy::new("default"),
            policies: HashMap::new(),
            min_key_trust_level: DEFAULT_MIN_TRUST_LEVEL,
            default_hash_algorithm: HashAlgorithm::Blake3,
        }
    }
    
    /// Add a trusted key to the context
    pub fn add_trusted_key(&self, key_pair: &KeyPair) -> CryptoResult<()> {
        self.key_storage.store_key(key_pair)
    }
    
    /// Add a verification policy
    pub fn add_policy(&mut self, policy: VerificationPolicy) {
        self.policies.insert(policy.name.clone(), policy);
    }
    
    /// Set the default policy
    pub fn set_default_policy(&mut self, policy: VerificationPolicy) {
        self.default_policy = policy;
    }
    
    /// Get a policy by name, or the default if not found
    pub fn get_policy(&self, name: Option<&str>) -> &VerificationPolicy {
        if let Some(name) = name {
            self.policies.get(name).unwrap_or(&self.default_policy)
        } else {
            &self.default_policy
        }
    }
    
    /// Set the minimum key trust level
    pub fn set_min_key_trust_level(&mut self, level: u8) {
        self.min_key_trust_level = level;
    }
    
    /// Set the default hash algorithm
    pub fn set_default_hash_algorithm(&mut self, algorithm: HashAlgorithm) {
        self.default_hash_algorithm = algorithm;
    }
    
    /// List all trusted keys
    pub fn list_trusted_keys(&self) -> CryptoResult<Vec<KeyInfo>> {
        self.key_storage.list_keys()
    }
    
    /// Verify a signature against trusted keys
    pub fn verify_signature(&self, data: &[u8], signature: &Signature) -> CryptoResult<VerificationResult> {
        // Attempt to load the key
        let key_pair = match self.key_storage.load_key(&signature.key_id) {
            Ok(key) => key,
            Err(CryptoError::KeyNotFound(_)) => {
                return Ok(VerificationResult::failure(format!(
                    "Key with ID {} not found in trusted key store", signature.key_id
                )));
            }
            Err(e) => return Err(e),
        };
        
        // Check key trust level
        if key_pair.info.trust_level < self.min_key_trust_level {
            return Ok(VerificationResult::failure(format!(
                "Key with ID {} has insufficient trust level", signature.key_id
            )));
        }
        
        // Check if key can be used for verification
        if !key_pair.can_use_for(KeyUsage::Verification) {
            return Ok(VerificationResult::failure(format!(
                "Key with ID {} cannot be used for verification", signature.key_id
            )));
        }
        
        // Create a verifier based on the signature algorithm
        let verified = match signature.algorithm {
            SignatureAlgorithm::Ed25519 => {
                // Get the public key
                let public_key_bytes = key_pair.export_public_key_bytes()?;
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&public_key_bytes);
                
                let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                    .map_err(|e| CryptoError::KeyError(format!("Invalid Ed25519 key: {}", e)))?;
                
                let provider = Ed25519SignatureProvider::from_public_key(
                    verifying_key, 
                    key_pair.info.id.clone()
                );
                
                provider.verify(data, signature)?
            }
        };
        
        if verified {
            let mut result = VerificationResult::success(TrustLevel::from_value(key_pair.info.trust_level));
            result.add_signature(signature.clone());
            result.add_key(key_pair.info.clone());
            Ok(result)
        } else {
            Ok(VerificationResult::failure("Signature verification failed".into()))
        }
    }
    
    /// Verify a trust chain against the default policy
    pub fn verify_chain(&self, chain: &TrustChain) -> CryptoResult<VerificationResult> {
        self.verify_chain_with_policy(chain, None)
    }
    
    /// Verify a trust chain against a specific policy
    pub fn verify_chain_with_policy(
        &self, 
        chain: &TrustChain, 
        policy_name: Option<&str>
    ) -> CryptoResult<VerificationResult> {
        let policy = self.get_policy(policy_name);
        
        // Check if we have enough signatures
        if chain.signatures.len() < policy.min_signatures {
            return Ok(VerificationResult::failure(format!(
                "Insufficient signatures: required {}, found {}",
                policy.min_signatures, chain.signatures.len()
            )));
        }
        
        // Check if we have enough unique signers
        let unique_signers = chain.count_unique_signers();
        if unique_signers < policy.min_unique_signers {
            return Ok(VerificationResult::failure(format!(
                "Insufficient unique signers: required {}, found {}",
                policy.min_unique_signers, unique_signers
            )));
        }
        
        // Verify each signature in the chain
        let mut result = VerificationResult::success(TrustLevel::None);
        let mut valid_signatures = 0;
        let mut highest_trust = 0;
        
        let mut verified_keys = HashSet::new();
        
        for signature in &chain.signatures {
            // Skip if policy doesn't allow this signature algorithm
            if !policy.allows_signature(signature) {
                if policy.mode == VerificationMode::Strict {
                    return Ok(VerificationResult::failure(format!(
                        "Signature algorithm {:?} not allowed by policy", signature.algorithm
                    )));
                }
                
                result.add_warning(
                    "signature_algorithm_not_allowed",
                    &format!("Signature algorithm {:?} not allowed by policy", signature.algorithm),
                    5
                );
                continue;
            }
            
            // Get the subject data to verify
            let subject_data = if let Some(hash) = &chain.subject_hash {
                // If we have a hash, just use the hash value
                hash.as_bytes()
            } else {
                // Otherwise use the subject string
                chain.subject.as_bytes()
            };
            
            // Verify the signature
            let sig_result = self.verify_signature(subject_data, signature);
            
            match sig_result {
                Ok(sig_result) if sig_result.is_valid => {
                    valid_signatures += 1;
                    result.add_signature(signature.clone());
                    
                    // Track the keys we've verified
                    for key in &sig_result.keys {
                        verified_keys.insert(key.id.clone());
                        result.add_key(key.clone());
                        
                        // Track highest trust level
                        if key.trust_level > highest_trust {
                            highest_trust = key.trust_level;
                        }
                    }
                }
                Ok(_) => {
                    if policy.mode == VerificationMode::Strict {
                        return Ok(VerificationResult::failure(
                            "Signature verification failed in strict mode".into()
                        ));
                    }
                    
                    result.add_warning(
                        "signature_verification_failed",
                        "A signature in the chain failed verification",
                        8
                    );
                }
                Err(e) => {
                    if policy.mode == VerificationMode::Strict {
                        return Err(e);
                    }
                    
                    result.add_warning(
                        "signature_verification_error",
                        &format!("Error verifying signature: {}", e),
                        9
                    );
                }
            }
        }
        
        // Check if we have enough valid signatures according to policy
        if valid_signatures < policy.min_signatures {
            return Ok(VerificationResult::failure(format!(
                "Insufficient valid signatures: required {}, found {}",
                policy.min_signatures, valid_signatures
            )));
        }
        
        // Check if we have enough unique verified signers
        if verified_keys.len() < policy.min_unique_signers {
            return Ok(VerificationResult::failure(format!(
                "Insufficient unique verified signers: required {}, found {}",
                policy.min_unique_signers, verified_keys.len()
            )));
        }
        
        // Set the overall trust level based on the highest trusted key
        result.trust_level = TrustLevel::from_value(highest_trust);
        
        // Check if the trust level meets the policy requirement
        if result.trust_level.as_value() < policy.min_trust_level.as_value() {
            if policy.mode == VerificationMode::Strict || policy.mode == VerificationMode::BestEffort {
                return Ok(VerificationResult::failure(format!(
                    "Insufficient trust level: required {:?}, found {:?}",
                    policy.min_trust_level, result.trust_level
                )));
            }
            
            result.add_warning(
                "insufficient_trust_level",
                &format!(
                    "Trust level {:?} is below the required level {:?}",
                    result.trust_level, policy.min_trust_level
                ),
                7
            );
        }
        
        // If we have warnings in permissive mode, keep the is_valid flag true
        // but add a metadata entry to indicate there were warnings
        if policy.mode == VerificationMode::Permissive && !result.warnings.is_empty() {
            result.add_metadata("has_warnings", "true");
            result.add_metadata("warning_count", &result.warnings.len().to_string());
        }
        
        Ok(result)
    }
    
    /// Verify a file against a trust chain
    pub fn verify_file<P: AsRef<Path>>(
        &self,
        file_path: P,
        chain: &TrustChain,
        policy_name: Option<&str>,
    ) -> CryptoResult<VerificationResult> {
        // Get the policy
        let policy = self.get_policy(policy_name);
        
        // Calculate the file hash
        let hash_algorithm = chain.hash_algorithm.unwrap_or(self.default_hash_algorithm);
        let file_hash = hash::hash_file_with_algorithm(file_path.as_ref(), hash_algorithm)?;
        let file_hash_hex = hash::format_hash_hex(&file_hash);
        
        // If the chain has a subject hash, verify it matches
        if let Some(subject_hash) = &chain.subject_hash {
            if subject_hash != &file_hash_hex {
                if policy.require_hash_verification || policy.mode == VerificationMode::Strict {
                    return Ok(VerificationResult::failure(format!(
                        "File hash mismatch: expected {}, calculated {}",
                        subject_hash, file_hash_hex
                    )));
                }
                
                let mut result = VerificationResult::success(TrustLevel::Low);
                result.add_warning(
                    "hash_mismatch",
                    &format!(
                        "File hash mismatch: expected {}, calculated {}",
                        subject_hash, file_hash_hex
                    ),
                    9
                );
                result.add_metadata("expected_hash", subject_hash);
                result.add_metadata("actual_hash", &file_hash_hex);
            }
        } else {
            // If there's no subject hash in the chain, add it now
            let mut chain_clone = chain.clone();
            chain_clone.subject_hash = Some(file_hash_hex.clone());
            chain_clone.hash_algorithm = Some(hash_algorithm);
            
            result.add_metadata("calculated_hash", &file_hash_hex);
            result.add_metadata("hash_algorithm", hash_algorithm.as_str());
        }
        
        // Now verify the chain itself
        let chain_result = self.verify_chain_with_policy(&chain, policy_name)?;
        
        // If chain verification failed, return that result
        if !chain_result.is_valid {
            return Ok(chain_result);
        }
        
        // Otherwise, blend the results
        let mut combined_result = chain_result;
        
        // Add file metadata
        combined_result.add_metadata("file_path", &file_path.as_ref().to_string_lossy());
        combined_result.add_metadata("file_hash", &file_hash_hex);
        combined_result.add_metadata("hash_algorithm", hash_algorithm.as_str());
        
        Ok(combined_result)
    }
    
    /// Verify data against a chain
    pub fn verify_data(
        &self,
        data: &[u8],
        chain: &TrustChain,
        policy_name: Option<&str>,
    ) -> CryptoResult<VerificationResult> {
        // Get the policy
        let policy = self.get_policy(policy_name);
        
        // Calculate data hash
        let hash_algorithm = chain.hash_algorithm.unwrap_or(self.default_hash_algorithm);
        let data_hash = hash::hash_with_algorithm(data, hash_algorithm)?;
        let data_hash_hex = hash::format_hash_hex(&data_hash);
        
        // Check the hash if provided
        if let Some(subject_hash) = &chain.subject_hash {
            if subject_hash != &data_hash_hex {
                if policy.require_hash_verification || policy.mode == VerificationMode::Strict {
                    return Ok(VerificationResult::failure(format!(
                        "Data hash mismatch: expected {}, calculated {}",
                        subject_hash, data_hash_hex
                    )));
                }
                
                let mut result = VerificationResult::success(TrustLevel::Low);
                result.add_warning(
                    "hash_mismatch",
                    &format!(
                        "Data hash mismatch: expected {}, calculated {}",
                        subject_hash, data_hash_hex
                    ),
                    9
                );
                result.add_metadata("expected_hash", subject_hash);
                result.add_metadata("actual_hash", &data_hash_hex);
            }
        }
        
        // Verify the signatures
        let chain_result = self.verify_chain_with_policy(chain, policy_name)?;
        
        // Add data metadata
        let mut result = chain_result;
        result.add_metadata("data_hash", &data_hash_hex);
        result.add_metadata("data_size", &data.len().to_string());
        result.add_metadata("hash_algorithm", hash_algorithm.as_str());
        
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyPair;
    use crate::signature::{SignatureAlgorithm, Ed25519SignatureProvider};
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};
    
    // Helper to create a test key
    fn create_test_key(name: &str, trust_level: u8) -> KeyPair {
        let key_pair = KeyPair::generate_ed25519(name).unwrap();
        
        // Set the trust level
        KeyPair {
            info: KeyInfo {
                trust_level,
                ..key_pair.info
            },
            private_key: key_pair.private_key,
        }
    }
    
    // Helper to create a test signature
    fn create_test_signature(key_pair: &KeyPair, data: &[u8]) -> Signature {
        let provider = Ed25519SignatureProvider::from_keypair(
            key_pair.private_key.as_ref().unwrap().to_ed25519_signing_key().unwrap(),
            key_pair.info.id.clone()
        );
        
        provider.sign(data, &key_pair.info.id).unwrap()
    }
    
    #[test]
    fn test_basic_signature_verification() {
        // Create a verification context
        let ctx = VerificationContext::new();
        
        // Create a test key and add it to the context
        let key = create_test_key("test-key", 2);
        ctx.add_trusted_key(&key).unwrap();
        
        // Create test data and sign it
        let data = b"Test data for verification";
        let signature = create_test_signature(&key, data);
        
        // Verify the signature
        let result = ctx.verify_signature(data, &signature).unwrap();
        
        // Check verification result
        assert!(result.is_valid);
        assert_eq!(result.trust_level, TrustLevel::Medium);
        assert_eq!(result.signatures.len(), 1);
        assert_eq!(result.keys.len(), 1);
        assert_eq!(result.keys[0].id, key.info.id);
        
        // Test with incorrect data
        let bad_data = b"Wrong data for verification";
        let result = ctx.verify_signature(bad_data, &signature).unwrap();
        
        // Should fail
        assert!(!result.is_valid);
    }
    
    #[test]
    fn test_trust_chain_verification() {
        // Create a verification context
        let mut ctx = VerificationContext::new();
        
        // Create test keys with different trust levels
        let key_low = create_test_key("low-trust", 1);
        let key_medium = create_test_key("medium-trust", 2);
        let key_high = create_test_key("high-trust", 3);
        
        // Add keys to the context
        ctx.add_trusted_key(&key_low).unwrap();
        ctx.add_trusted_key(&key_medium).unwrap();
        ctx.add_trusted_key(&key_high).unwrap();
        
        // Create a subject and chain
        let subject = "test-package-1.0.0";
        let chain = TrustChain::new("test-chain", subject, "package");
        
        // Test with no signatures
        let result = ctx.verify_chain(&chain).unwrap();
        assert!(!result.is_valid);
        
        // Add one signature
        let mut chain = chain;
        let signature = create_test_signature(&key_medium, subject.as_bytes());
        chain.add_signature(signature);
        
        // Verify with default policy (requires Medium trust)
        let result = ctx.verify_chain(&chain).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.trust_level, TrustLevel::Medium);
        
        // Add a second signature
        let signature2 = create_test_signature(&key_high, subject.as_bytes());
        chain.add_signature(signature2);
        
        // Verify with strict policy requiring 2 signatures
        let strict_policy = VerificationPolicy::strict("strict", 2);
        ctx.add_policy(strict_policy);
        
        let result = ctx.verify_chain_with_policy(&chain, Some("strict")).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.trust_level, TrustLevel::High);
        assert_eq!(result.signatures.len(), 2);
    }
    
    #[test]
    fn test_verification_modes() {
        // Create a verification context
        let mut ctx = VerificationContext::new();
        
        // Create test keys
        let key1 = create_test_key("key1", 2);
        let key2 = create_test_key("key2", 3);
        let untrusted_key = create_test_key("untrusted", 0);
        
        // Add trusted keys to the context
        ctx.add_trusted_key(&key1).unwrap();
        ctx.add_trusted_key(&key2).unwrap();
        
        // Create a subject and chain
        let subject = "test-package-2.0.0";
        let mut chain = TrustChain::new("test-chain-modes", subject, "package");
        
        // Add a signature from a trusted key
        let sig1 = create_test_signature(&key1, subject.as_bytes());
        chain.add_signature(sig1);
        
        // Add a signature from an untrusted key (not in the context)
        let sig2 = create_test_signature(&untrusted_key, subject.as_bytes());
        chain.add_signature(sig2);
        
        // Test with strict mode
        let strict_policy = VerificationPolicy::new("strict")
            .with_mode(VerificationMode::Strict);
        ctx.add_policy(strict_policy);
        
        // In strict mode, verification should fail due to untrusted key
        let result = ctx.verify_chain_with_policy(&chain, Some("strict")).unwrap();
        assert!(!result.is_valid);
        
        // Test with best-effort mode
        let best_effort_policy = VerificationPolicy::new("best-effort")
            .with_mode(VerificationMode::BestEffort);
        ctx.add_policy(best_effort_policy);
        
        // In best-effort mode, verification should succeed with the one good signature
        let result = ctx.verify_chain_with_policy(&chain, Some("best-effort")).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.signatures.len(), 1);  // Only one valid signature counted
        assert_eq!(result.trust_level, TrustLevel::Medium);
        
        // Test with permissive mode
        let permissive_policy = VerificationPolicy::new("permissive")
            .with_mode(VerificationMode::Permissive);
        ctx.add_policy(permissive_policy);
        
        // In permissive mode, verification should succeed with warnings
        let result = ctx.verify_chain_with_policy(&chain, Some("permissive")).unwrap();
        assert!(result.is_valid);
        assert!(!result.warnings.is_empty());
        assert!(result.metadata.contains_key("has_warnings"));
    }
    
    #[test]
    fn test_file_verification() {
        // Create a verification context
        let ctx = VerificationContext::new();
        
        // Create a test key
        let key = create_test_key("file-signing-key", 3);
        ctx.add_trusted_key(&key).unwrap();
        
        // Create a temp file
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_content = b"Test file content for verification";
        temp_file.write_all(test_content).unwrap();
        temp_file.flush().unwrap();
        
        // Calculate the file hash
        let hash_algorithm = HashAlgorithm::Blake3;
        let file_hash = hash::hash_file_with_algorithm(temp_file.path(), hash_algorithm).unwrap();
        let file_hash_hex = hash::format_hash_hex(&file_hash);
        
        // Create a trust chain with the file hash
        let mut chain = TrustChain::new(
            "file-chain",
            temp_file.path().to_string_lossy().as_ref(),
            "file"
        );
        chain = chain.with_subject_hash(&file_hash_hex, hash_algorithm);
        
        // Sign the hash
        let signature = create_test_signature(&key, file_hash_hex.as_bytes());
        chain.add_signature(signature);
        
        // Verify the file
        let result = ctx.verify_file(temp_file.path(), &chain, None).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.trust_level, TrustLevel::High);
        assert_eq!(result.signatures.len(), 1);
        assert!(result.metadata.contains_key("file_hash"));
        assert_eq!(result.metadata.get("file_hash").unwrap(), &file_hash_hex);
        
        // Test with modified file
        let mut modified_file = NamedTempFile::new().unwrap();
        let modified_content = b"Modified content that doesn't match the hash";
        modified_file.write_all(modified_content).unwrap();
        modified_file.flush().unwrap();
        
        // Verify the modified file - should fail due to hash mismatch
        let result = ctx.verify_file(modified_file.path(), &chain, None).unwrap();
        assert!(!result.is_valid);
        assert!(result.error.as_ref().unwrap().contains("hash mismatch"));
    }
    
    #[test]
    fn test_data_verification() {
        // Create a verification context
        let ctx = VerificationContext::new();
        
        // Create a test key
        let key = create_test_key("data-signing-key", 3);
        ctx.add_trusted_key(&key).unwrap();
        
        // Create test data
        let test_data = b"Test data content for verification";
        
        // Calculate the data hash
        let hash_algorithm = HashAlgorithm::Blake3;
        let data_hash = hash::hash_with_algorithm(test_data, hash_algorithm).unwrap();
        let data_hash_hex = hash::format_hash_hex(&data_hash);
        
        // Create a trust chain with the data hash
        let mut chain = TrustChain::new(
            "data-chain",
            "test-data-subject",
            "data"
        );
        chain = chain.with_subject_hash(&data_hash_hex, hash_algorithm);
        
        // Sign the hash
        let signature = create_test_signature(&key, data_hash_hex.as_bytes());
        chain.add_signature(signature);
        
        // Verify the data
        let result = ctx.verify_data(test_data, &chain, None).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.trust_level, TrustLevel::High);
        assert_eq!(result.signatures.len(), 1);
        assert!(result.metadata.contains_key("data_hash"));
        assert_eq!(result.metadata.get("data_hash").unwrap(), &data_hash_hex);
        
        // Test with modified data
        let modified_data = b"Modified data that doesn't match the hash";
        let result = ctx.verify_data(modified_data, &chain, None).unwrap();
        assert!(!result.is_valid);
        assert!(result.error.as_ref().unwrap().contains("hash mismatch"));
    }
    
    #[test]
    fn test_hash_algorithm_validation() {
        // Create a verification context
        let mut ctx = VerificationContext::new();
        
        // Create a test key
        let key = create_test_key("hash-algo-key", 3);
        ctx.add_trusted_key(&key).unwrap();
        
        // Test data
        let test_data = b"Test data for hash algorithm validation";
        
        // Create chains with different hash algorithms
        let blake3_hash = hash::hash_with_algorithm(test_data, HashAlgorithm::Blake3).unwrap();
        let blake3_hash_hex = hash::format_hash_hex(&blake3_hash);
        
        let sha256_hash = hash::hash_with_algorithm(test_data, HashAlgorithm::Sha256).unwrap();
        let sha256_hash_hex = hash::format_hash_hex(&sha256_hash);
        
        // Create chains with different algorithms
        let mut blake3_chain = TrustChain::new("blake3-chain", "test-data", "data")
            .with_subject_hash(&blake3_hash_hex, HashAlgorithm::Blake3);
        blake3_chain.add_signature(create_test_signature(&key, blake3_hash_hex.as_bytes()));
        
        let mut sha256_chain = TrustChain::new("sha256-chain", "test-data", "data")
            .with_subject_hash(&sha256_hash_hex, HashAlgorithm::Sha256);
        sha256_chain.add_signature(create_test_signature(&key, sha256_hash_hex.as_bytes()));
        
        // Create a policy that requires BLAKE3
        let blake3_policy = VerificationPolicy::new("blake3-only")
            .with_mode(VerificationMode::Strict);
        
        let blake3_only_required = blake3_policy.clone();
        blake3_only_required.required_hash_algorithms = Some(vec![HashAlgorithm::Blake3]);
        ctx.add_policy(blake3_policy);
        
        // Verify with the correct algorithm
        let result = ctx.verify_data(test_data, &blake3_chain, None).unwrap();
        assert!(result.is_valid);
        
        // Verify with SHA-256
        let result = ctx.verify_data(test_data, &sha256_chain, None).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.metadata.get("hash_algorithm").unwrap(), "SHA-256");
    }
    
    #[test]
    fn test_policy_based_verification() {
        // Create a verification context
        let mut ctx = VerificationContext::new();
        
        // Create test keys with different trust levels
        let key_low = create_test_key("policy-low", 1);
        let key_medium = create_test_key("policy-medium", 2);
        let key_high = create_test_key("policy-high", 3);
        
        // Add keys to the trusted store
        ctx.add_trusted_key(&key_low).unwrap();
        ctx.add_trusted_key(&key_medium).unwrap();
        ctx.add_trusted_key(&key_high).unwrap();
        
        // Create test data
        let test_data = b"Test data for policy-based verification";
        let data_hash = hash::hash_with_algorithm(test_data, HashAlgorithm::Blake3).unwrap();
        let data_hash_hex = hash::format_hash_hex(&data_hash);
        
        // Create a chain with signatures from all three keys
        let mut chain = TrustChain::new("policy-chain", "test-data", "data")
            .with_subject_hash(&data_hash_hex, HashAlgorithm::Blake3);
        
        // Add signatures from all keys
        chain.add_signature(create_test_signature(&key_low, data_hash_hex.as_bytes()));
        chain.add_signature(create_test_signature(&key_medium, data_hash_hex.as_bytes()));
        chain.add_signature(create_test_signature(&key_high, data_hash_hex.as_bytes()));
        
        // Create policies with different trust level requirements
        let low_policy = VerificationPolicy::new("low-trust")
            .with_min_trust_level(TrustLevel::Low);
        
        let medium_policy = VerificationPolicy::new("medium-trust")
            .with_min_trust_level(TrustLevel::Medium);
        
        let high_policy = VerificationPolicy::new("high-trust")
            .with_min_trust_level(TrustLevel::High);
        
        let max_policy = VerificationPolicy::new("max-trust")
            .with_min_trust_level(TrustLevel::Maximum);
        
        // Add policies to context
        ctx.add_policy(low_policy);
        ctx.add_policy(medium_policy);
        ctx.add_policy(high_policy);
        ctx.add_policy(max_policy);
        
        // Test with low trust requirement
        let result = ctx.verify_data(test_data, &chain, Some("low-trust")).unwrap();
        assert!(result.is_valid);
        
        // Test with medium trust requirement
        let result = ctx.verify_data(test_data, &chain, Some("medium-trust")).unwrap();
        assert!(result.is_valid);
        
        // Test with high trust requirement
        let result = ctx.verify_data(test_data, &chain, Some("high-trust")).unwrap();
        assert!(result.is_valid);
        
        // Test with maximum trust requirement (should fail as our max is High)
        let result = ctx.verify_data(test_data, &chain, Some("max-trust")).unwrap();
        assert!(!result.is_valid);
        assert!(result.error.as_ref().unwrap().contains("Insufficient trust level"));
    }
    
    #[test]
    fn test_verification_error_cases() {
        // Create a verification context
        let mut ctx = VerificationContext::new();
        
        // Create test key
        let key = create_test_key("error-test-key", 2);
        ctx.add_trusted_key(&key).unwrap();
        
        // Test data
        let test_data = b"Test data for error cases";
        let data_hash = hash::hash_with_algorithm(test_data, HashAlgorithm::Blake3).unwrap();
        let data_hash_hex = hash::format_hash_hex(&data_hash);
        
        // Error case 1: Empty chain (no signatures)
        let empty_chain = TrustChain::new("empty-chain", "test-data", "data")
            .with_subject_hash(&data_hash_hex, HashAlgorithm::Blake3);
        
        let result = ctx.verify_data(test_data, &empty_chain, None).unwrap();
        assert!(!result.is_valid);
        assert!(result.error.as_ref().unwrap().contains("Insufficient signatures"));
        
        // Error case 2: Non-existent key
        let mut unknown_key_chain = TrustChain::new("unknown-key-chain", "test-data", "data")
            .with_subject_hash(&data_hash_hex, HashAlgorithm::Blake3);
        
        // Create a key that's not in the trusted store
        let unknown_key = create_test_key("unknown-key", 3);
        let unknown_sig = create_test_signature(&unknown_key, data_hash_hex.as_bytes());
        unknown_key_chain.add_signature(unknown_sig);
        
        // Should fail with untrusted key error
        let result = ctx.verify_data(test_data, &unknown_key_chain, None).unwrap();
        assert!(!result.is_valid);
        
        // Error case 3: Multiple signatures required but not provided
        let multi_sig_policy = VerificationPolicy::strict("multi-sig", 2);
        ctx.add_policy(multi_sig_policy);
        
        // Only one signature provided
        let mut single_sig_chain = TrustChain::new("single-sig-chain", "test-data", "data")
            .with_subject_hash(&data_hash_hex, HashAlgorithm::Blake3);
        single_sig_chain.add_signature(create_test_signature(&key, data_hash_hex.as_bytes()));
        
        let result = ctx.verify_data(test_data, &single_sig_chain, Some("multi-sig")).unwrap();
        assert!(!result.is_valid);
        assert!(result.error.as_ref().unwrap().contains("Insufficient valid signatures"));
        
        // Error case 4: Expired key
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        
        // Create an expired key
        let expired_key_pair = KeyPair::generate_ed25519("expired-key").unwrap();
        let expired_key_pair = KeyPair {
            info: KeyInfo {
                expires_at: Some(now - 3600), // Expired 1 hour ago
                trust_level: 3,
                ..expired_key_pair.info
            },
            private_key: expired_key_pair.private_key,
        };
        
