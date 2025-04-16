        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
            
        Self {
            key_id,
            value,
            algorithm,
            timestamp,
            metadata: metadata.unwrap_or_default(),
        }
    }

    /// Get the signature value as bytes
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Get the signature timestamp as a DateTime
    pub fn timestamp_datetime(&self) -> chrono::DateTime<chrono::Utc> {
        let timestamp = std::time::UNIX_EPOCH + std::time::Duration::from_secs(self.timestamp);
        chrono::DateTime::from(timestamp)
    }

    /// Format the signature as a hexadecimal string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.value)
    }

    /// Parse a hexadecimal signature string
    pub fn from_hex(
        key_id: String,
        hex_str: &str,
        algorithm: SignatureAlgorithm,
        metadata: Option<std::collections::HashMap<String, String>>,
    ) -> CryptoResult<Self> {
        let value = hex::decode(hex_str).map_err(|e| {
            CryptoError::SignatureError(format!("Invalid hex signature: {}", e))
        })?;
        
        Ok(Self::new(key_id, value, algorithm, metadata))
    }

    /// Serialize the signature to JSON
    pub fn to_json(&self) -> CryptoResult<String> {
        serde_json::to_string(self).map_err(|e| {
            CryptoError::JsonError(e)
        })
    }

    /// Deserialize a signature from JSON
    pub fn from_json(json: &str) -> CryptoResult<Self> {
        serde_json::from_str(json).map_err(|e| {
            CryptoError::JsonError(e)
        })
    }
}

/// Trait for digital signature operations
pub trait SignatureProvider {
    /// Sign data and return a Signature
    fn sign(&self, data: &[u8], key_id: &str) -> CryptoResult<Signature>;
    
    /// Verify a signature over the provided data
    fn verify(&self, data: &[u8], signature: &Signature) -> CryptoResult<bool>;
    
    /// Get the algorithm used by this provider
    fn algorithm(&self) -> SignatureAlgorithm;
}

/// Ed25519 signature provider
pub struct Ed25519SignatureProvider {
    signing_key: Option<SigningKey>,
    verifying_key: VerifyingKey,
    key_id: String,
}

impl Ed25519SignatureProvider {
    /// Create a new Ed25519 signature provider with a randomly generated key pair
    pub fn generate() -> CryptoResult<Self> {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = VerifyingKey::from(&signing_key);
        
        // Generate a key ID from the public key
        let key_bytes = verifying_key.to_bytes();
        let key_id = format!("ed25519:{}", hex::encode(&key_bytes[0..8]));
        
        Ok(Self {
            signing_key: Some(signing_key),
            verifying_key,
            key_id,
        })
    }
    
    /// Create a new Ed25519 signature provider from an existing key pair
    pub fn from_keypair(signing_key: SigningKey, key_id: String) -> Self {
        let verifying_key = VerifyingKey::from(&signing_key);
        
        Self {
            signing_key: Some(signing_key),
            verifying_key,
            key_id,
        }
    }
    
    /// Create a new Ed25519 signature verifier with only a public key
    pub fn from_public_key(verifying_key: VerifyingKey, key_id: String) -> Self {
        Self {
            signing_key: None,
            verifying_key,
            key_id,
        }
    }
    
    /// Get the public key
    pub fn public_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
    
    /// Get the key ID
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    
    /// Export the public key as bytes
    pub fn export_public_key(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
    
    /// Export the private key as bytes, if available
    pub fn export_private_key(&self) -> CryptoResult<[u8; 32]> {
        if let Some(signing_key) = &self.signing_key {
            Ok(signing_key.to_bytes())
        } else {
            Err(CryptoError::KeyError("Private key not available".into()))
        }
    }
}

impl SignatureProvider for Ed25519SignatureProvider {
    fn sign(&self, data: &[u8], key_id: &str) -> CryptoResult<Signature> {
        // Check that we have a signing key
        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            CryptoError::SignatureError("No signing key available".into())
        })?;
        
        // Check that the key ID matches
        if key_id != self.key_id {
            return Err(CryptoError::SignatureError(format!(
                "Key ID mismatch: expected {}, got {}", 
                self.key_id, key_id
            )));
        }
        
        // Sign the data
        let signature = signing_key.sign(data);
        
        // Create the Signature object
        Ok(Signature::new(
            self.key_id.clone(),
            signature.to_bytes().to_vec(),
            SignatureAlgorithm::Ed25519,
            None,
        ))
    }
    
    fn verify(&self, data: &[u8], signature: &Signature) -> CryptoResult<bool> {
        // Check that the algorithm matches
        if signature.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(CryptoError::SignatureError(format!(
                "Algorithm mismatch: expected {:?}, got {:?}",
                SignatureAlgorithm::Ed25519, signature.algorithm
            )));
        }
        
        // Convert the signature bytes to an Ed25519Signature
        let ed_signature = Ed25519Signature::from_slice(&signature.value)
            .map_err(|e| CryptoError::SignatureError(format!("Invalid signature: {}", e)))?;
        
        // Verify the signature
        match self.verifying_key.verify(data, &ed_signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }
}

/// Sign data using Ed25519
pub fn sign_data_ed25519(data: &[u8], signing_key: &SigningKey, key_id: &str) -> Signature {
    let signature = signing_key.sign(data);
    
    Signature::new(
        key_id.to_string(),
        signature.to_bytes().to_vec(),
        SignatureAlgorithm::Ed25519,
        None,
    )
}

/// Verify data with an Ed25519 signature
pub fn verify_data_ed25519(data: &[u8], signature: &Signature, verifying_key: &VerifyingKey) -> CryptoResult<bool> {
    // Check that the algorithm matches
    if signature.algorithm != SignatureAlgorithm::Ed25519 {
        return Err(CryptoError::SignatureError(format!(
            "Algorithm mismatch: expected {:?}, got {:?}",
            SignatureAlgorithm::Ed25519, signature.algorithm
        )));
    }
    
    // Convert the signature bytes to an Ed25519Signature
    let ed_signature = Ed25519Signature::from_slice(&signature.value)
        .map_err(|e| CryptoError::SignatureError(format!("Invalid signature: {}", e)))?;
    
    // Verify the signature
    match verifying_key.verify(data, &ed_signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ed25519_sign_verify() {
        let provider = Ed25519SignatureProvider::generate().unwrap();
        let data = b"TrustChain test data";
        
        let signature = provider.sign(data, provider.key_id()).unwrap();
        
        // Verify with the same provider
        let valid = provider.verify(data, &signature).unwrap();
        assert!(valid);
        
        // Verify with a different data
        let invalid = provider.verify(b"Different data", &signature).unwrap();
        assert!(!invalid);
    }
    
    #[test]
    fn test_signature_serialization() {
        let provider = Ed25519SignatureProvider::generate().unwrap();
        let data = b"TrustChain serialization test";
        
        let signature = provider.sign(data, provider.key_id()).unwrap();
        
        // Test JSON serialization
        let json = signature.to_json().unwrap();
        let deserialized = Signature::from_json(&json).unwrap();
        
        assert_eq!(signature.key_id, deserialized.key_id);
        assert_eq!(signature.value, deserialized.value);
        assert_eq!(signature.algorithm, deserialized.algorithm);
        assert_eq!(signature.timestamp, deserialized.timestamp);
    }
    
    #[test]
    fn test_hex_conversion() {
        let provider = Ed25519SignatureProvider::generate().unwrap();
        let data = b"TrustChain hex test";
        
        let signature = provider.sign(data, provider.key_id()).unwrap();
        
        // Test hex conversion
        let hex = signature.to_hex();
        let parsed = Signature::from_hex(
            signature.key_id.clone(),
            &hex,
            signature.algorithm,
            Some(signature.metadata.clone()),
        ).unwrap();
        
        assert_eq!(signature.value, parsed.value);
    }
}
