/// Key usage types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyUsage {
    /// Signing keys are used to create digital signatures
    Signing,
    /// Verification keys are used to verify digital signatures
    Verification,
    /// Encryption keys are used to encrypt data
    Encryption,
    /// Decryption keys are used to decrypt data
    Decryption,
    /// Authentication keys are used for authentication protocols
    Authentication,
}

impl KeyUsage {
    /// Get the string identifier for this key usage
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyUsage::Signing => "signing",
            KeyUsage::Verification => "verification",
            KeyUsage::Encryption => "encryption",
            KeyUsage::Decryption => "decryption",
            KeyUsage::Authentication => "authentication",
        }
    }

    /// Parse a string into a KeyUsage
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "signing" => Some(KeyUsage::Signing),
            "verification" => Some(KeyUsage::Verification),
            "encryption" => Some(KeyUsage::Encryption),
            "decryption" => Some(KeyUsage::Decryption),
            "authentication" => Some(KeyUsage::Authentication),
            _ => None,
        }
    }
}

impl fmt::Display for KeyUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Key metadata and information
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Unique identifier for the key
    pub id: String,

    /// The type of key (algorithm)
    pub key_type: KeyType,

    /// Key usages - what this key can be used for
    pub usages: Vec<KeyUsage>,

    /// Descriptive name for the key
    pub name: String,

    /// Optional description of the key
    pub description: Option<String>,

    /// Entity that owns or controls this key
    pub owner: Option<String>,

    /// When the key was created (seconds since UNIX epoch)
    pub created_at: u64,

    /// When the key expires (seconds since UNIX epoch), if any
    pub expires_at: Option<u64>,

    /// Trust level associated with this key (higher is more trusted)
    pub trust_level: u8,

    /// Whether this key has private key material available
    pub has_private_key: bool,

    /// Additional metadata associated with this key
    pub metadata: HashMap<String, String>,
}

impl KeyInfo {
    /// Create new key info
    pub fn new(
        id: String,
        key_type: KeyType,
        usages: Vec<KeyUsage>,
        name: String,
        has_private_key: bool,
    ) -> Self {
        Self {
            id,
            key_type,
            usages,
            name,
            description: None,
            owner: None,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            expires_at: None,
            trust_level: 0,
            has_private_key,
            metadata: HashMap::new(),
        }
    }

    /// Check if key has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();
            expires_at < now
        } else {
            false
        }
    }

    /// Check if key can be used for a specific purpose
    pub fn can_use_for(&self, usage: KeyUsage) -> bool {
        !self.is_expired() && self.usages.contains(&usage)
    }

    /// Convert to JSON
    pub fn to_json(&self) -> CryptoResult<String> {
        serde_json::to_string(self).map_err(|e| CryptoError::JsonError(e))
    }

    /// Parse from JSON
    pub fn from_json(json: &str) -> CryptoResult<Self> {
        serde_json::from_str(json).map_err(|e| CryptoError::JsonError(e))
    }

    /// Add metadata to the key
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    /// Set key description
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// Set key owner
    pub fn with_owner(mut self, owner: &str) -> Self {
        self.owner = Some(owner.to_string());
        self
    }

    /// Set key expiration time
    pub fn with_expiration(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set trust level
    pub fn with_trust_level(mut self, level: u8) -> Self {
        self.trust_level = level;
        self
    }
}

/// Private key material that must be kept secure
#[derive(Clone, Serialize, Deserialize)]
pub struct PrivateKeyMaterial {
    /// Raw key bytes
    pub key_bytes: Vec<u8>,
    
    /// Key type
    pub key_type: KeyType,
    
    /// Optional passphrase to encrypt the key (not stored, just used for encryption)
    #[serde(skip)]
    pub passphrase: Option<String>,
}

impl PrivateKeyMaterial {
    /// Create new private key material
    pub fn new(key_bytes: Vec<u8>, key_type: KeyType) -> Self {
        Self {
            key_bytes,
            key_type,
            passphrase: None,
        }
    }

    /// Add a passphrase for encryption
    pub fn with_passphrase(mut self, passphrase: &str) -> Self {
        self.passphrase = Some(passphrase.to_string());
        self
    }

    /// Convert to Ed25519 signing key
    pub fn to_ed25519_signing_key(&self) -> CryptoResult<SigningKey> {
        if self.key_type != KeyType::Ed25519 {
            return Err(CryptoError::KeyError(format!(
                "Expected Ed25519 key, got {:?}", self.key_type
            )));
        }

        if self.key_bytes.len() != 32 {
            return Err(CryptoError::KeyError(format!(
                "Invalid Ed25519 key length: expected 32, got {}", self.key_bytes.len()
            )));
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.key_bytes);
        
        SigningKey::from_bytes(&bytes).map_err(|e| {
            CryptoError::KeyError(format!("Invalid Ed25519 key: {}", e))
        })
    }
}

/// Key pair containing both public and private components
pub struct KeyPair {
    /// Public key information
    pub info: KeyInfo,
    
    /// Private key material (optional)
    pub private_key: Option<PrivateKeyMaterial>,
}

impl KeyPair {
    /// Create a new key pair
    pub fn new(info: KeyInfo, private_key: Option<PrivateKeyMaterial>) -> Self {
        Self { info, private_key }
    }

    /// Generate a new Ed25519 key pair
    pub fn generate_ed25519(name: &str) -> CryptoResult<Self> {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = VerifyingKey::from(&signing_key);
        
        // Generate a key ID from the public key
        let key_bytes = verifying_key.to_bytes();
        let key_id = format!("ed25519:{}", hex::encode(&key_bytes[0..8]));
        
        let info = KeyInfo::new(
            key_id.clone(),
            KeyType::Ed25519,
            vec![KeyUsage::Signing, KeyUsage::Verification],
            name.to_string(),
            true,
        );
        
        let private_key = PrivateKeyMaterial::new(
            signing_key.to_bytes().to_vec(),
            KeyType::Ed25519,
        );
        
        Ok(Self::new(info, Some(private_key)))
    }

    /// Export public key as bytes
    pub fn export_public_key_bytes(&self) -> CryptoResult<Vec<u8>> {
        match self.info.key_type {
            KeyType::Ed25519 => {
                if let Some(private_key) = &self.private_key {
                    let signing_key = private_key.to_ed25519_signing_key()?;
                    let verifying_key = VerifyingKey::from(&signing_key);
                    Ok(verifying_key.to_bytes().to_vec())
                } else {
                    // In a real implementation, we would store the public key
                    // For now, just return an error if we don't have the private key
                    Err(CryptoError::KeyError("No key material available".into()))
                }
            }
        }
    }

    /// Export private key as bytes
    pub fn export_private_key_bytes(&self) -> CryptoResult<Vec<u8>> {
        if let Some(private_key) = &self.private_key {
            Ok(private_key.key_bytes.clone())
        } else {
            Err(CryptoError::KeyError("No private key available".into()))
        }
    }

    /// Check if this key pair can be used for a specific purpose
    pub fn can_use_for(&self, usage: KeyUsage) -> bool {
        self.info.can_use_for(usage) && 
        // For signing, encryption, and decryption, we need a private key
        match usage {
            KeyUsage::Signing | KeyUsage::Decryption => self.private_key.is_some(),
            _ => true,
        }
    }
}

/// Trait for key storage
pub trait KeyStorage {
    /// Store a key pair
    fn store_key(&self, key_pair: &KeyPair) -> CryptoResult<()>;
    
    /// Load a key pair by ID
    fn load_key(&self, key_id: &str) -> CryptoResult<KeyPair>;
    
    /// List all keys
    fn list_keys(&self) -> CryptoResult<Vec<KeyInfo>>;
    
    /// Delete a key
    fn delete_key(&self, key_id: &str) -> CryptoResult<()>;
}

/// Simple file-based key storage
pub struct FileKeyStorage {
    /// Directory where keys are stored
    pub directory: std::path::PathBuf,
}

impl FileKeyStorage {
    /// Create a new file-based key storage
    pub fn new<P: AsRef<Path>>(directory: P) -> CryptoResult<Self> {
        let directory = directory.as_ref().to_path_buf();
        
        // Create the directory if it doesn't exist
        if !directory.exists() {
            fs::create_dir_all(&directory)
                .map_err(|e| CryptoError::IoError(e))?;
        }
        
        Ok(Self { directory })
    }
    
    /// Get the file path for a key
    fn get_key_path(&self, key_id: &str) -> std::path::PathBuf {
        self.directory.join(format!("{}.json", key_id))
    }
}

impl KeyStorage for FileKeyStorage {
    fn store_key(&self, key_pair: &KeyPair) -> CryptoResult<()> {
        let key_path = self.get_key_path(&key_pair.info.id);
        
        // Serialize the key info
        let key_info_json = key_pair.info.to_json()?;
        
        // Serialize private key if present
        let private_key_json = if let Some(private_key) = &key_pair.private_key {
            serde_json::to_string(private_key)
                .map_err(|e| CryptoError::JsonError(e))?
        } else {
            "null".to_string()
        };
        
        // Create the combined JSON
        let combined_json = format!(
            "{{\"info\":{},\"private_key\":{}}}",
            key_info_json, private_key_json
        );
        
        // Write to file
        let mut file = File::create(key_path)
            .map_err(|e| CryptoError::IoError(e))?;
        
        file.write_all(combined_json.as_bytes())
            .map_err(|e| CryptoError::IoError(e))?;
        
        Ok(())
    }
    
    fn load_key(&self, key_id: &str) -> CryptoResult<KeyPair> {
        let key_path = self.get_key_path(key_id);
        
        if !key_path.exists() {
            return Err(CryptoError::KeyNotFound(
                format!("Key with ID {} not found", key_id)
            ));
        }
        
        // Read the file
        let mut file = File::open(key_path)
            .map_err(|e| CryptoError::IoError(e))?;
        
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| CryptoError::IoError(e))?;
        
        // Parse the JSON
        let json_value: serde_json::Value = serde_json::from_str(&contents)
            .map_err(|e| CryptoError::JsonError(e))?;
        
        // Extract the key info
        let info_json = json_value.get("info")
            .ok_or_else(|| CryptoError::KeyError(
                "Invalid key file format: missing 'info' field".into()
            ))?;
        
        let info: KeyInfo = serde_json::from_value(info_json.clone())
            .map_err(|e| CryptoError::JsonError(e))?;
        
        // Extract the private key if present
        let private_key = if let Some(private_key_json) = json_value.get("private_key") {
            if private_key_json.is_null() {
                None
            } else {
                let private_key: PrivateKeyMaterial = serde_json::from_value(private_key_json.clone())
                    .map_err(|e| CryptoError::JsonError(e))?;
                Some(private_key)
            }
        } else {
            None
        };
        
        Ok(KeyPair::new(info, private_key))
    }
    
    fn list_keys(&self) -> CryptoResult<Vec<KeyInfo>> {
        let mut keys = Vec::new();
        
        if !self.directory.exists() {
            return Ok(keys);
        }
        
        // Read all .json files in the directory
        for entry in fs::read_dir(&self.directory)
            .map_err(|e| CryptoError::IoError(e))? {
            
            let entry = entry.map_err(|e| CryptoError::IoError(e))?;
            let path = entry.path();
            
            // Only process .json files
            if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
                // Try to load the key
                match self.load_key(&path.file_stem().unwrap().to_string_lossy()) {
                    Ok(key_pair) => keys.push(key_pair.info),
                    Err(e) => {
                        // Log the error but continue processing other keys
                        eprintln!("Error loading key from {}: {}", path.display(), e);
                    }
                }
            }
        }
        
        Ok(keys)
    }
    
    fn delete_key(&self, key_id: &str) -> CryptoResult<()> {
        let key_path = self.get_key_path(key_id);
        
        if !key_path.exists() {
            return Err(CryptoError::KeyNotFound(
                format!("Key with ID {} not found", key_id)
            ));
        }
        
        fs::remove_file(key_path)
            .map_err(|e| CryptoError::IoError(e))?;
        
        Ok(())
    }
}

/// In-memory key storage for testing and ephemeral use
pub struct MemoryKeyStorage {
    /// Map of key ID to key pair
    keys: std::sync::RwLock<HashMap<String, KeyPair>>,
}

impl MemoryKeyStorage {
    /// Create a new in-memory key storage
    pub fn new() -> Self {
        Self {
            keys: std::sync::RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemoryKeyStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStorage for MemoryKeyStorage {
    fn store_key(&self, key_pair: &KeyPair) -> CryptoResult<()> {
        let mut keys = self.keys.write().map_err(|_| 
            CryptoError::KeyError("Failed to acquire write lock".into())
        )?;
        
        // Clone the key pair and store it
        let key_id = key_pair.info.id.clone();
        keys.insert(key_id, KeyPair {
            info: key_pair.info.clone(),
            private_key: key_pair.private_key.clone(),
        });
        
        Ok(())
    }
    
    fn load_key(&self, key_id: &str) -> CryptoResult<KeyPair> {
        let keys = self.keys.read().map_err(|_| 
            CryptoError::KeyError("Failed to acquire read lock".into())
        )?;
        
        // Look up the key pair
        if let Some(key_pair) = keys.get(key_id) {
            Ok(KeyPair {
                info: key_pair.info.clone(),
                private_key: key_pair.private_key.clone(),
            })
        } else {
            Err(CryptoError::KeyNotFound(
                format!("Key with ID {} not found", key_id)
            ))
        }
    }
    
    fn list_keys(&self) -> CryptoResult<Vec<KeyInfo>> {
        let keys = self.keys.read().map_err(|_| 
            CryptoError::KeyError("Failed to acquire read lock".into())
        )?;
        
        // Collect all key infos
        let key_infos = keys.values()
            .map(|key_pair| key_pair.info.clone())
            .collect();
        
        Ok(key_infos)
    }
    
    fn delete_key(&self, key_id: &str) -> CryptoResult<()> {
        let mut keys = self.keys.write().map_err(|_| 
            CryptoError::KeyError("Failed to acquire write lock".into())
        )?;
        
        // Remove the key if it exists
        if keys.remove(key_id).is_some() {
            Ok(())
        } else {
            Err(CryptoError::KeyNotFound(
                format!("Key with ID {} not found", key_id)
            ))
        }
    }
}

/// KeyPair serialization/deserialization functions
impl KeyPair {
    /// Serialize to JSON
    pub fn to_json(&self) -> CryptoResult<String> {
        let info_json = self.info.to_json()?;
        
        let private_key_json = if let Some(private_key) = &self.private_key {
            serde_json::to_string(private_key)
                .map_err(|e| CryptoError::JsonError(e))?
        } else {
            "null".to_string()
        };
        
        Ok(format!(
            "{{\"info\":{},\"private_key\":{}}}",
            info_json, private_key_json
        ))
    }
    
    /// Deserialize from JSON
    pub fn from_json(json: &str) -> CryptoResult<Self> {
        let json_value: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| CryptoError::JsonError(e))?;
        
        // Extract the key info
        let info_json = json_value.get("info")
            .ok_or_else(|| CryptoError::KeyError(
                "Invalid key pair JSON: missing 'info' field".into()
            ))?;
        
        let info: KeyInfo = serde_json::from_value(info_json.clone())
            .map_err(|e| CryptoError::JsonError(e))?;
        
        // Extract the private key if present
        let private_key = if let Some(private_key_json) = json_value.get("private_key") {
            if private_key_json.is_null() {
                None
            } else {
                let private_key: PrivateKeyMaterial = serde_json::from_value(private_key_json.clone())
                    .map_err(|e| CryptoError::JsonError(e))?;
                Some(private_key)
            }
        } else {
            None
        };
        
        Ok(Self::new(info, private_key))
    }
    
    /// Export to PEM format (public key only)
    pub fn export_public_key_pem(&self) -> CryptoResult<String> {
        let public_key_bytes = self.export_public_key_bytes()?;
        
        let key_type = match self.info.key_type {
            KeyType::Ed25519 => "ED25519 PUBLIC KEY",
        };
        
        let base64_data = base64::encode(&public_key_bytes);
        let pem = format!(
            "-----BEGIN {}-----\n{}\n-----END {}-----\n",
            key_type, base64_data, key_type
        );
        
        Ok(pem)
    }
    
    /// Export to PEM format (private key, if available)
    pub fn export_private_key_pem(&self) -> CryptoResult<String> {
        let private_key_bytes = self.export_private_key_bytes()?;
        
        let key_type = match self.info.key_type {
            KeyType::Ed25519 => "ED25519 PRIVATE KEY",
        };
        
        let base64_data = base64::encode(&private_key_bytes);
        let pem = format!(
            "-----BEGIN {}-----\n{}\n-----END {}-----\n",
            key_type, base64_data, key_type
        );
        
        Ok(pem)
    }
}

/// Functions for importing keys
pub mod import {
    use super::*;
    
    /// Import an Ed25519 key pair from raw bytes
    pub fn ed25519_from_bytes(
        private_key_bytes: &[u8],
        name: &str,
    ) -> CryptoResult<KeyPair> {
        if private_key_bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyFormat(format!(
                "Invalid Ed25519 private key length: expected 32, got {}",
                private_key_bytes.len()
            )));
        }
        
        // Create the signing key
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(private_key_bytes);
        
        let signing_key = SigningKey::from_bytes(&bytes).map_err(|e| {
            CryptoError::KeyError(format!("Invalid Ed25519 key: {}", e))
        })?;
        
        let verifying_key = VerifyingKey::from(&signing_key);
        
        // Generate a key ID from the public key
        let key_bytes = verifying_key.to_bytes();
        let key_id = format!("ed25519:{}", hex::encode(&key_bytes[0..8]));
        
        // Create key info
        let info = KeyInfo::new(
            key_id.clone(),
            KeyType::Ed25519,
            vec![KeyUsage::Signing, KeyUsage::Verification],
            name.to_string(),
            true,
        );
        
        // Create private key material
        let private_key = PrivateKeyMaterial::new(
            private_key_bytes.to_vec(),
            KeyType::Ed25519,
        );
        
        Ok(KeyPair::new(info, Some(private_key)))
    }
    
    /// Import an Ed25519 key from a PEM-encoded string
    pub fn from_pem(pem_str: &str, name: &str) -> CryptoResult<KeyPair> {
        // Determine if this is a public or private key
        let is_private = pem_str.contains("PRIVATE KEY");
        let is_ed25519 = pem_str.contains("ED25519");
        
        if !is_ed25519 {
            return Err(CryptoError::InvalidKeyFormat(
                "Unsupported key type. Only Ed25519 keys are supported".into()
            ));
        }
        
        // Extract the base64-encoded content between the headers
        let content_regex = regex::Regex::new(
            r"-----BEGIN .*?-----\s*(.*?)\s*-----END .*?-----"
        ).map_err(|e| {
            CryptoError::KeyError(format!("Regex error: {}", e))
        })?;
        
        let base64_content = content_regex.captures(pem_str)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().replace("\n", ""))
            .ok_or_else(|| {
                CryptoError::InvalidKeyFormat("Invalid PEM format".into())
            })?;
        
        // Decode the base64 content
        let key_bytes = base64::decode(&base64_content)
            .map_err(|e| {
                CryptoError::InvalidKeyFormat(format!("Invalid base64: {}", e))
            })?;
        
        if is_private {
            // For private key, just import directly
            ed25519_from_bytes(&key_bytes, name)
        } else {
            // For public key, we need to create a KeyPair with only public key info
            if key_bytes.len() != 32 {
                return Err(CryptoError::InvalidKeyFormat(format!(
                    "Invalid Ed25519 public key length: expected 32, got {}",
                    key_bytes.len()
                )));
            }
            
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&key_bytes);
            
            let verifying_key = VerifyingKey::from_bytes(&bytes)
                .map_err(|e| {
                    CryptoError::KeyError(format!("Invalid Ed25519 key: {}", e))
                })?;
            
            // Generate a key ID from the public key
            let key_id = format!("ed25519:{}", hex::encode(&key_bytes[0..8]));
            
            // Create key info
            let info = KeyInfo::new(
                key_id.clone(),
                KeyType::Ed25519,
                vec![KeyUsage::Verification],
                name.to_string(),
                false,
            );
            
            Ok(KeyPair::new(info, None))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_key_generation() {
        // Generate a new Ed25519 key pair
        let key_pair = KeyPair::generate_ed25519("test-key").unwrap();
        
        // Check key info
        assert_eq!(key_pair.info.key_type, KeyType::Ed25519);
        assert_eq!(key_pair.info.name, "test-key");
        assert!(key_pair.info.has_private_key);
        assert!(key_pair.info.usages.contains(&KeyUsage::Signing));
        assert!(key_pair.info.usages.contains(&KeyUsage::Verification));
        
        // Check private key
        assert!(key_pair.private_key.is_some());
        let private_key = key_pair.private_key.unwrap();
        assert_eq!(private_key.key_type, KeyType::Ed25519);
        assert_eq!(private_key.key_bytes.len(), 32);
        
        // Test exporting public key
        let public_key_bytes = key_pair.export_public_key_bytes().unwrap();
        assert_eq!(public_key_bytes.len(), 32);
    }
    
    #[test]
    fn test_key_usage() {
        // Generate a new Ed25519 key pair
        let key_pair = KeyPair::generate_ed25519("test-usage").unwrap();
        
        // Check usages
        assert!(key_pair.can_use_for(KeyUsage::Signing));
        assert!(key_pair.can_use_for(KeyUsage::Verification));
        assert!(!key_pair.can_use_for(KeyUsage::Encryption));
        assert!(!key_pair.can_use_for(KeyUsage::Decryption));
        
        // Create a public key only pair
        let public_key_bytes = key_pair.export_public_key_bytes().unwrap();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&public_key_bytes);
        
        let verifying_key = VerifyingKey::from_bytes(&bytes).unwrap();
        let public_only = Ed25519SignatureProvider::from_public_key(
            verifying_key, 
            key_pair.info.id.clone()
        );
        
        // Create a KeyPair from this provider
        let public_only_pair = KeyPair::new(
            KeyInfo::new(
                key_pair.info.id.clone(),
                KeyType::Ed25519,
                vec![KeyUsage::Verification],
                "public-only".to_string(),
                false,
            ),
            None,
        );
        
        // Check usages for public-only key
        assert!(!public_only_pair.can_use_for(KeyUsage::Signing));
        assert!(public_only_pair.can_use_for(KeyUsage::Verification));
    }
    
    #[test]
    fn test_key_serialization() {
        // Generate a new Ed25519 key pair
        let key_pair = KeyPair::generate_ed25519("test-json").unwrap();
        
        // Serialize to JSON
        let json = key_pair.to_json().unwrap();
        
        // Deserialize from JSON
        let deserialized = KeyPair::from_json(&json).unwrap();
        
        // Check that deserialized key matches original
        assert_eq!(deserialized.info.id, key_pair.info.id);
        assert_eq!(deserialized.info.key_type, key_pair.info.key_type);
        assert_eq!(deserialized.info.name, key_pair.info.name);
        
        // Check private key material
        assert!(deserialized.private_key.is_some());
        let original_key_bytes = &key_pair.private_key.as_ref().unwrap().key_bytes;
        let deserialized_key_bytes = &deserialized.private_key.as_ref().unwrap().key_bytes;
        assert_eq!(deserialized_key_bytes, original_key_bytes);
    }
    
    #[test]
    fn test_pem_export_import() {
        // Generate a new Ed25519 key pair
        let key_pair = KeyPair::generate_ed25519("test-pem").unwrap();
        
        // Export to PEM format
        let public_pem = key_pair.export_public_key_pem().unwrap();
        let private_pem = key_pair.export_private_key_pem().unwrap();
        
        // Check PEM formats
        assert!(public_pem.contains("BEGIN ED25519 PUBLIC KEY"));
        assert!(private_pem.contains("BEGIN ED25519 PRIVATE KEY"));
        
        // Import from PEM
        let imported_public = import::from_pem(&public_pem, "imported-public").unwrap();
        let imported_private = import::from_pem(&private_pem, "imported-private").unwrap();
        
        // Check imported keys
        assert_eq!(imported_public.info.key_type, KeyType::Ed25519);
        assert_eq!(imported_private.info.key_type, KeyType::Ed25519);
        
        // Public key import should not have private key
        assert!(!imported_public.info.has_private_key);
        assert!(imported_public.private_key.is_none());
        
        // Private key import should have private key
        assert!(imported_private.info.has_private_key);
        assert!(imported_private.private_key.is_some());
        
        // Exported public keys should match
        let original_public = key_pair.export_public_key_bytes().unwrap();
        let imported_public_bytes = imported_private.export_public_key_bytes().unwrap();
        assert_eq!(original_public, imported_public_bytes);
    }
    
    #[test]
    fn test_memory_key_storage() {
        // Create memory key storage
        let storage = MemoryKeyStorage::new();
        
        // Generate keys
        let key1 = KeyPair::generate_ed25519("key1").unwrap();
        let key2 = KeyPair::generate_ed25519("key2").unwrap();
        
        // Store keys
        storage.store_key(&key1).unwrap();
        storage.store_key(&key2).unwrap();
        
        // List keys
        let keys = storage.list_keys().unwrap();
        assert_eq!(keys.len(), 2);
        
        // Check if keys are in the list
        let key1_id = key1.info.id.clone();
        let key2_id = key2.info.id.clone();
        let key_ids: Vec<String> = keys.iter().map(|k| k.id.clone()).collect();
        assert!(key_ids.contains(&key1_id));
        assert!(key_ids.contains(&key2_id));
        
        // Load a key
        let loaded = storage.load_key(&key1_id).unwrap();
        assert_eq!(loaded.info.id, key1.info.id);
        assert_eq!(loaded.info.name, key1.info.name);
        
        // Delete a key
        storage.delete_key(&key1_id).unwrap();
        let keys = storage.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].id, key2_id);
        
        // Try to load deleted key
        assert!(storage.load_key(&key1_id).is_err());
    }
    
    #[test]
    fn test_file_key_storage() {
        // Create temporary directory for key storage
        let temp_dir = TempDir::new().unwrap();
        let storage = FileKeyStorage::new(temp_dir.path()).unwrap();
        
        // Generate keys
        let key1 = KeyPair::generate_ed25519("file-key1").unwrap();
        let key2 = KeyPair::generate_ed25519("file-key2").unwrap();
        
        // Store keys
        storage.store_key(&key1).unwrap();
        storage.store_key(&key2).unwrap();
        
        // List keys
        let keys = storage.list_keys().unwrap();
        assert_eq!(keys.len(), 2);
        
        // Check if keys are in the list
        let key1_id = key1.info.id.clone();
        let key2_id = key2.info.id.clone();
        let key_ids: Vec<String> = keys.iter().map(|k| k.id.clone()).collect();
        assert!(key_ids.contains(&key1_id));
        assert!(key_ids.contains(&key2_id));
        
        // Load a key
        let loaded = storage.load_key(&key1_id).unwrap();
        assert_eq!(loaded.info.id, key1.info.id);
        assert_eq!(loaded.info.name, key1.info.name);
        
        // Check that private key material was preserved
        assert!(loaded.private_key.is_some());
        
        // Delete a key
        storage.delete_key(&key1_id).unwrap();
        let keys = storage.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].id, key2_id);
        
        // Try to load deleted key
        assert!(storage.load_key(&key1_id).is_err());
        
        // Verify file was deleted
        let key_path = storage.get_key_path(&key1_id);
        assert!(!key_path.exists());
    }
    
    #[test]
    fn test_key_expiration() {
        // Get current time
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        
        // Create a key that expires in the future
        let future_key = KeyPair::generate_ed25519("future-expiry").unwrap();
        let future_key = KeyPair {
            info: KeyInfo {
                expires_at: Some(now + 3600), // Expires in 1 hour
                ..future_key.info
            },
            private_key: future_key.private_key,
        };
        
        // Check that it's not expired
        assert!(!future_key.info.is_expired());
        
        // Check that it can be used
        assert!(future_key.can_use_for(KeyUsage::Signing));
        assert!(future_key.can_use_for(KeyUsage::Verification));
        
        // Create a key that has already expired
        let past_key = KeyPair::generate_ed25519("past-expiry").unwrap();
        let past_key = KeyPair {
            info: KeyInfo {
                expires_at: Some(now - 3600), // Expired 1 hour ago
                ..past_key.info
            },
            private_key: past_key.private_key,
        };
        
        // Check that it's expired
        assert!(past_key.info.is_expired());
        
        // Check that it can't be used
        assert!(!past_key.can_use_for(KeyUsage::Signing));
        assert!(!past_key.can_use_for(KeyUsage::Verification));
        
        // Create a key expiring exactly now (should be expired)
        let now_key = KeyPair::generate_ed25519("now-expiry").unwrap();
        let now_key = KeyPair {
            info: KeyInfo {
                expires_at: Some(now), // Expires now
                ..now_key.info
            },
            private_key: now_key.private_key,
        };
        
        // Check that it's expired
        assert!(now_key.info.is_expired());
        
        // Store and retrieve an expired key
        let storage = MemoryKeyStorage::new();
        storage.store_key(&past_key).unwrap();
        
        // Should be able to load it
        let loaded = storage.load_key(&past_key.info.id).unwrap();
        
        // But it should be marked as expired
        assert!(loaded.info.is_expired());
        assert!(!loaded.can_use_for(KeyUsage::Signing));
    }
    
    #[test]
    fn test_key_info_metadata() {
        // Create a key with metadata
        let key = KeyPair::generate_ed25519("metadata-test").unwrap();
        
        // Add metadata using fluent API
        let key_info = key.info.clone()
            .with_description("Test key with metadata")
            .with_owner("Test User")
            .with_trust_level(5)
            .with_metadata("environment", "test")
            .with_metadata("purpose", "unit testing");
        
        // Check metadata
        assert_eq!(key_info.description.as_deref(), Some("Test key with metadata"));
        assert_eq!(key_info.owner.as_deref(), Some("Test User"));
        assert_eq!(key_info.trust_level, 5);
        assert_eq!(key_info.metadata.get("environment").unwrap(), "test");
        assert_eq!(key_info.metadata.get("purpose").unwrap(), "unit testing");
        
        // Serialize and deserialize
        let json = key_info.to_json().unwrap();
        let deserialized = KeyInfo::from_json(&json).unwrap();
        
        // Check metadata preserved
        assert_eq!(deserialized.description, key_info.description);
        assert_eq!(deserialized.owner, key_info.owner);
        assert_eq!(deserialized.trust_level, key_info.trust_level);
        assert_eq!(deserialized.metadata.get("environment"), key_info.metadata.get("environment"));
        assert_eq!(deserialized.metadata.get("purpose"), key_info.metadata.get("purpose"));
    }
}
