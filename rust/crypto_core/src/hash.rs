//! Hash functionality for TrustChain crypto core.
//!
//! This module provides hash functionality for TrustChain, including:
//! - Trait definitions for hash operations
//! - Implementation of BLAKE3 and SHA-256 hash algorithms
//! - Functions for hashing data, files, and other content

use blake3::Hasher as Blake3Hasher;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use crate::error::{CryptoError, CryptoResult};

/// Size of BLAKE3 hash output in bytes
pub const BLAKE3_HASH_SIZE: usize = 32;

/// Size of SHA-256 hash output in bytes
pub const SHA256_HASH_SIZE: usize = 32;

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// BLAKE3 cryptographic hash function
    Blake3,
    /// SHA-256 cryptographic hash function
    Sha256,
}

impl HashAlgorithm {
    /// Get the string identifier for this algorithm
    pub fn as_str(&self) -> &'static str {
        match self {
            HashAlgorithm::Blake3 => "BLAKE3",
            HashAlgorithm::Sha256 => "SHA-256",
        }
    }

    /// Parse a string into a HashAlgorithm
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "BLAKE3" => Some(HashAlgorithm::Blake3),
            "SHA-256" | "SHA256" => Some(HashAlgorithm::Sha256),
            _ => None,
        }
    }

    /// Get the output size of this hash algorithm in bytes
    pub fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Blake3 => BLAKE3_HASH_SIZE,
            HashAlgorithm::Sha256 => SHA256_HASH_SIZE,
        }
    }
}

/// A trait for hash functions
pub trait HashFunction {
    /// Hash the provided data
    fn hash_data(&self, data: &[u8]) -> CryptoResult<Vec<u8>>;
    
    /// Hash the contents of a file
    fn hash_file<P: AsRef<Path>>(&self, path: P) -> CryptoResult<Vec<u8>>;
    
    /// Get the algorithm identifier
    fn algorithm(&self) -> HashAlgorithm;
    
    /// Reset the hash state
    fn reset(&mut self);
}

/// BLAKE3 hash function implementation
pub struct Blake3Hash {
    hasher: Blake3Hasher,
}

impl Blake3Hash {
    /// Create a new BLAKE3 hasher
    pub fn new() -> Self {
        Self {
            hasher: Blake3Hasher::new(),
        }
    }
}

impl Default for Blake3Hash {
    fn default() -> Self {
        Self::new()
    }
}

impl HashFunction for Blake3Hash {
    fn hash_data(&self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut hasher = self.hasher.clone();
        hasher.update(data);
        let hash = hasher.finalize();
        Ok(hash.as_bytes().to_vec())
    }
    
    fn hash_file<P: AsRef<Path>>(&self, path: P) -> CryptoResult<Vec<u8>> {
        let mut file = File::open(path)
            .map_err(|e| CryptoError::IoError(e))?;
        
        let mut hasher = self.hasher.clone();
        let mut buffer = [0; 8192]; // 8KB buffer
        
        loop {
            let bytes_read = file.read(&mut buffer)
                .map_err(|e| CryptoError::IoError(e))?;
            
            if bytes_read == 0 {
                break;
            }
            
            hasher.update(&buffer[..bytes_read]);
        }
        
        let hash = hasher.finalize();
        Ok(hash.as_bytes().to_vec())
    }
    
    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Blake3
    }
    
    fn reset(&mut self) {
        self.hasher = Blake3Hasher::new();
    }
}

/// SHA-256 hash function implementation
pub struct Sha256Hash {
    hasher: Sha256,
}

impl Sha256Hash {
    /// Create a new SHA-256 hasher
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }
}

impl Default for Sha256Hash {
    fn default() -> Self {
        Self::new()
    }
}

impl HashFunction for Sha256Hash {
    fn hash_data(&self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut hasher = self.hasher.clone();
        hasher.update(data);
        let result = hasher.finalize();
        Ok(result.to_vec())
    }
    
    fn hash_file<P: AsRef<Path>>(&self, path: P) -> CryptoResult<Vec<u8>> {
        let mut file = File::open(path)
            .map_err(|e| CryptoError::IoError(e))?;
        
        let mut hasher = self.hasher.clone();
        let mut buffer = [0; 8192]; // 8KB buffer
        
        loop {
            let bytes_read = file.read(&mut buffer)
                .map_err(|e| CryptoError::IoError(e))?;
            
            if bytes_read == 0 {
                break;
            }
            
            hasher.update(&buffer[..bytes_read]);
        }
        
        let result = hasher.finalize();
        Ok(result.to_vec())
    }
    
    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha256
    }
    
    fn reset(&mut self) {
        self.hasher = Sha256::new();
    }
}

/// Create a new hash function for the specified algorithm
pub fn create_hash_function(algorithm: HashAlgorithm) -> Box<dyn HashFunction> {
    match algorithm {
        HashAlgorithm::Blake3 => Box::new(Blake3Hash::new()),
        HashAlgorithm::Sha256 => Box::new(Sha256Hash::new()),
    }
}

/// Hash data using the specified algorithm
pub fn hash_with_algorithm(data: &[u8], algorithm: HashAlgorithm) -> CryptoResult<Vec<u8>> {
    let hash_function = create_hash_function(algorithm);
    hash_function.hash_data(data)
}

/// Hash a file using the specified algorithm
pub fn hash_file_with_algorithm<P: AsRef<Path>>(path: P, algorithm: HashAlgorithm) -> CryptoResult<Vec<u8>> {
    let hash_function = create_hash_function(algorithm);
    hash_function.hash_file(path)
}

/// Format a hash as a hexadecimal string
pub fn format_hash_hex(hash: &[u8]) -> String {
    hex::encode(hash)
}

/// Parse a hexadecimal hash string into bytes
pub fn parse_hash_hex(hex_str: &str) -> CryptoResult<Vec<u8>> {
    hex::decode(hex_str).map_err(|e| {
        CryptoError::HashError(format!("Invalid hex hash string: {}", e))
    })
}

/// Calculate the hash of multiple pieces of data using the specified algorithm
pub fn hash_multiple(data_pieces: &[&[u8]], algorithm: HashAlgorithm) -> CryptoResult<Vec<u8>> {
    match algorithm {
        HashAlgorithm::Blake3 => {
            let mut hasher = Blake3Hasher::new();
            for data in data_pieces {
                hasher.update(data);
            }
            let hash = hasher.finalize();
            Ok(hash.as_bytes().to_vec())
        },
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            for data in data_pieces {
                hasher.update(data);
            }
            let result = hasher.finalize();
            Ok(result.to_vec())
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_blake3_hash_data() {
        let data = b"TrustChain test data";
        let hasher = Blake3Hash::new();
        let hash = hasher.hash_data(data).unwrap();
        
        assert_eq!(hash.len(), BLAKE3_HASH_SIZE);
        
        // Test idempotence
        let hash2 = hasher.hash_data(data).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_sha256_hash_data() {
        let data = b"TrustChain test data";
        let hasher = Sha256Hash::new();
        let hash = hasher.hash_data(data).unwrap();
        
        assert_eq!(hash.len(), SHA256_HASH_SIZE);
        
        // Test idempotence
        let hash2 = hasher.hash_data(data).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hash_file() {
        let data = b"TrustChain file test data";
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(data).unwrap();
        
        let file_path = temp_file.path();
        
        // Test BLAKE3
        let blake3_hasher = Blake3Hash::new();
        let file_hash = blake3_hasher.hash_file(file_path).unwrap();
        let data_hash = blake3_hasher.hash_data(data).unwrap();
        assert_eq!(file_hash, data_hash);
        
        // Test SHA-256
        let sha256_hasher = Sha256Hash::new();
        let file_hash = sha256_hasher.hash_file(file_path).unwrap();
        let data_hash = sha256_hasher.hash_data(data).unwrap();
        assert_eq!(file_hash, data_hash);
    }

    #[test]
    fn test_hash_multiple() {
        let data1 = b"Trust";
        let data2 = b"Chain";
        
        // Test BLAKE3
        let blake3_combined = hash_multiple(&[data1, data2], HashAlgorithm::Blake3).unwrap();
        let blake3_single = hash_with_algorithm(b"TrustChain", HashAlgorithm::Blake3).unwrap();
        assert_ne!(blake3_combined, blake3_single);
        
        // Test SHA-256
        let sha256_combined = hash_multiple(&[data1, data2], HashAlgorithm::Sha256).unwrap();
        let sha256_single = hash_with_algorithm(b"TrustChain", HashAlgorithm::Sha256).unwrap();
        assert_ne!(sha256_combined, sha256_single);
    }

    #[test]
    fn test_hex_encoding() {
        let data = b"TrustChain hex test";
        let hash = hash_with_algorithm(data, HashAlgorithm::Blake3).unwrap();
        
        let hex_str = format_hash_hex(&hash);
        let parsed_hash = parse_hash_hex(&hex_str).unwrap();
        
        assert_eq!(hash, parsed_hash);
    }
}

