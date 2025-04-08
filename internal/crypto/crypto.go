// Package crypto provides interfaces and implementations for cryptographic
// operations used in TrustChain, including verification, signing, and hash
// functions. It acts as a Go interface to the high-performance Rust crypto core.
package crypto

import (
	"context"
	"crypto/ed25519"
	"io"
	"time"
)

// Signature represents a cryptographic signature with metadata
type Signature struct {
	// KeyID is the identifier for the key that created this signature
	KeyID string

	// Value contains the raw signature bytes
	Value []byte

	// Algorithm identifies the signature algorithm used
	Algorithm string

	// Timestamp is when the signature was created
	Timestamp time.Time

	// Metadata contains additional information about the signature
	Metadata map[string]string
}

// VerificationResult represents the outcome of a verification operation
type VerificationResult struct {
	// Valid indicates if the signature is valid
	Valid bool

	// Error contains any error encountered during verification
	Error error

	// KeyInfo contains metadata about the verification key used
	KeyInfo KeyInfo

	// Timestamp is when the verification was performed
	Timestamp time.Time

	// Warnings contains non-fatal issues discovered during verification
	Warnings []string
}

// KeyInfo contains metadata about a cryptographic key
type KeyInfo struct {
	// ID is the key identifier
	ID string

	// Owner identifies the entity that controls the key
	Owner string

	// CreatedAt is when the key was created
	CreatedAt time.Time

	// ExpiresAt is when the key expires (zero value means no expiration)
	ExpiresAt time.Time

	// KeyType identifies the type of key (e.g., "ed25519")
	KeyType string

	// TrustLevel indicates the level of trust associated with this key
	TrustLevel int

	// Metadata contains additional key information
	Metadata map[string]string
}

// Signer provides interfaces for creating cryptographic signatures
type Signer interface {
	// Sign creates a signature over the given data
	Sign(data []byte) (Signature, error)

	// SignWithMetadata creates a signature with additional metadata
	SignWithMetadata(data []byte, metadata map[string]string) (Signature, error)

	// GetPublicKey returns the public verification key
	GetPublicKey() []byte

	// GetKeyInfo returns metadata about the signing key
	GetKeyInfo() KeyInfo
}

// Verifier provides interfaces for verifying cryptographic signatures
type Verifier interface {
	// Verify checks if a signature is valid for the given data
	Verify(data []byte, signature Signature) (VerificationResult, error)

	// VerifyWithContext performs verification with additional context information
	VerifyWithContext(ctx context.Context, data []byte, signature Signature) (VerificationResult, error)

	// AddTrustedKey adds a key to the trusted key store
	AddTrustedKey(keyID string, publicKey []byte, keyInfo KeyInfo) error

	// RemoveTrustedKey removes a key from the trusted key store
	RemoveTrustedKey(keyID string) error
}

// HashFunction defines an interface for cryptographic hash functions
type HashFunction interface {
	// Hash calculates a hash over the provided data
	Hash(data []byte) ([]byte, error)

	// HashReader calculates a hash from a reader's content
	HashReader(reader io.Reader) ([]byte, error)

	// Algorithm returns the name of the hash algorithm
	Algorithm() string

	// Reset clears the current hash state
	Reset()
}

// KeyManager handles operations related to cryptographic key lifecycle
type KeyManager interface {
	// GenerateKey creates a new cryptographic key pair
	GenerateKey(keyType string, metadata map[string]string) (KeyInfo, error)

	// ImportKey imports an existing key
	ImportKey(privateKey []byte, keyType string, metadata map[string]string) (KeyInfo, error)

	// ExportKey exports a key in serialized form
	ExportKey(keyID string, withPrivate bool) ([]byte, error)

	// ListKeys returns all keys managed by this key manager
	ListKeys() ([]KeyInfo, error)

	// GetSigner returns a Signer interface for the specified key
	GetSigner(keyID string) (Signer, error)
}

// Service provides a facade for all cryptographic operations
type Service interface {
	// GetSigner returns a Signer for creating signatures
	GetSigner(keyID string) (Signer, error)

	// GetVerifier returns a Verifier for checking signatures
	GetVerifier() Verifier

	// GetHashFunction returns a HashFunction for the specified algorithm
	GetHashFunction(algorithm string) (HashFunction, error)

	// GetKeyManager returns the key management interface
	GetKeyManager() KeyManager
}

// NewService creates a new crypto service instance
func NewService() (Service, error) {
	// TODO: Implement service creation that connects to the Rust crypto core
	return nil, nil
}

