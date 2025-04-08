// Package policy implements TrustChain's policy engine and trust zone management.
// It provides interfaces for defining, evaluating, and enforcing policies that
// govern verification requirements across different parts of the software supply chain.
package policy

import (
	"context"
	"time"

	"github.com/trustchain/trustchain/internal/crypto"
)

// RuleID uniquely identifies a policy rule
type RuleID string

// ZoneID uniquely identifies a trust zone
type ZoneID string

// Severity represents the criticality level of policy violations
type Severity string

const (
	// SeverityInfo indicates an informational policy finding
	SeverityInfo Severity = "info"

	// SeverityWarning indicates a warning-level policy finding
	SeverityWarning Severity = "warning"

	// SeverityError indicates an error-level policy violation
	SeverityError Severity = "error"

	// SeverityCritical indicates a critical policy violation
	SeverityCritical Severity = "critical"
)

// PolicyContext contains the data used during policy evaluation
type PolicyContext struct {
	// ArtifactID identifies the artifact being evaluated
	ArtifactID string

	// ArtifactPath is the filesystem path or URL to the artifact
	ArtifactPath string

	// ArtifactType specifies the type of artifact
	ArtifactType string

	// Signatures contains cryptographic signatures attached to the artifact
	Signatures []crypto.Signature

	// Attestations contains attestations for the artifact
	Attestations []Attestation

	// Dependencies lists artifact dependencies
	Dependencies []Dependency

	// Metadata contains additional evaluation context
	Metadata map[string]interface{}
}

// Attestation represents a statement about an artifact's properties
type Attestation struct {
	// ID uniquely identifies this attestation
	ID string

	// ArtifactID identifies the attested artifact
	ArtifactID string

	// Issuer identifies who created the attestation
	Issuer string
	
	// Type identifies the attestation type
	Type string

	// Timestamp is when the attestation was created
	Timestamp time.Time

	// Signature verifies the attestation's authenticity
	Signature crypto.Signature

	// Statements contains the attested properties
	Statements map[string]interface{}
}

// Dependency represents a relationship between artifacts
type Dependency struct {
	// ID uniquely identifies the dependency
	ID string

	// Name is the dependency name
	Name string

	// Version is the dependency version
	Version string

	// Type is the dependency type
	Type string
	
	// ArtifactID identifies the dependency's artifact
	ArtifactID string

	// Path is how the dependency is referenced
	Path string

	// InclusionMethod describes how the dependency is included
	InclusionMethod string
}

// RuleResult represents the outcome of evaluating a policy rule
type RuleResult struct {
	// RuleID identifies the evaluated rule
	RuleID RuleID

	// Passed indicates if the rule passed
	Passed bool

	// Severity indicates the importance of the rule
	Severity Severity

	// Message provides human-readable explanation
	Message string

	// Details contains structured information about the result
	Details map[string]interface{}

	// Remediation suggests how to fix a violation
	Remediation string
}

// EvaluationResult represents the outcome of policy evaluation
type EvaluationResult struct {
	// ZoneID identifies the trust zone used for evaluation
	ZoneID ZoneID

	// Timestamp is when evaluation occurred
	Timestamp time.Time

	// Passed indicates if all required rules passed
	Passed bool

	// RuleResults contains individual rule evaluation results
	RuleResults []RuleResult

	// CriticalRuleViolations counts critical violations
	CriticalRuleViolations int

	// ErrorRuleViolations counts error violations
	ErrorRuleViolations int

	// WarningRuleViolations counts warning violations
	WarningRuleViolations int

	// InfoRuleViolations counts informational findings
	InfoRuleViolations int
}

// Rule defines a policy rule that can be evaluated
type Rule interface {
	// ID returns the rule's unique identifier
	ID() RuleID

	// Name returns the rule's human-readable name
	Name() string

	// Description returns a detailed explanation of the rule
	Description() string

	// Severity returns the rule's severity level
	Severity() Severity

	// Evaluate checks if the rule is satisfied
	Evaluate(ctx context.Context, policyCtx PolicyContext) (RuleResult, error)

	// GetMetadata returns rule metadata
	GetMetadata() map[string]string
}

// CompositeRule is a rule composed of other rules
type CompositeRule interface {
	Rule

	// AddRule adds a rule to this composite
	AddRule(rule Rule) error

	// RemoveRule removes a rule from this composite
	RemoveRule(ruleID RuleID) error

	// GetRules returns all component rules
	GetRules() []Rule
}

// RuleOperator defines the logical relationship between rules
type RuleOperator string

const (
	// RuleOperatorAnd requires all rules to pass
	RuleOperatorAnd RuleOperator = "and"

	// RuleOperatorOr requires at least one rule to pass
	RuleOperatorOr RuleOperator = "or"

	// RuleOperatorNot negates the result of a rule
	RuleOperatorNot RuleOperator = "not"
)

// RuleFactory creates rules from configuration
type RuleFactory interface {
	// CreateRule creates a rule from configuration
	CreateRule(config map[string]interface{}) (Rule, error)

	// GetRuleTypes returns supported rule types
	GetRuleTypes() []string
}

// TrustZone defines verification requirements for a project area
type TrustZone struct {
	// ID uniquely identifies the zone
	ID ZoneID

	// Name is the zone's human-readable name
	Name string

	// Description explains the zone's purpose
	Description string

	// PathPatterns defines filesystem patterns in this zone
	PathPatterns []string

	// ArtifactPatterns defines artifact patterns in this zone
	ArtifactPatterns []string

	// RequiredRules lists rules that must pass
	RequiredRules []Rule

	// RecommendedRules lists rules that should pass
	RecommendedRules []Rule

	// Metadata contains additional zone information
	Metadata map[string]string
}

// ZoneManager handles trust zone configuration
type ZoneManager interface {
	// CreateZone creates a new trust zone
	CreateZone(zone TrustZone) error

	// UpdateZone updates an existing trust zone
	UpdateZone(zone TrustZone) error

	// DeleteZone removes a trust zone
	DeleteZone(id ZoneID) error

	// GetZone retrieves a trust zone by ID
	GetZone(id ZoneID) (TrustZone, error)

	// ListZones returns all defined trust zones
	ListZones() ([]TrustZone, error)

	// FindZoneForPath finds the applicable zone for a path
	FindZoneForPath(path string) (TrustZone, error)

	// FindZoneForArtifact finds the applicable zone for an artifact
	FindZoneForArtifact(artifactID string, artifactType string) (TrustZone, error)
}

// ViolationHandler processes policy violations
type ViolationHandler interface {
	// HandleViolation processes a policy violation
	HandleViolation(ctx context.Context, result EvaluationResult) error

	// GetRemediation suggests remediation for a violation
	GetRemediation(ruleID RuleID, context map[string]interface{}) (string, error)
}

// PolicyEngine evaluates policies against artifacts
type PolicyEngine interface {
	// Evaluate checks if an artifact satisfies policy
	Evaluate(ctx context.Context, policyCtx PolicyContext) (EvaluationResult, error)

	// EvaluateWithZone checks if an artifact satisfies a specific zone's policy
	EvaluateWithZone(ctx context.Context, policyCtx PolicyContext, zoneID ZoneID) (EvaluationResult, error)

	// RegisterRule adds a rule to the engine
	RegisterRule(rule Rule) error

	// UnregisterRule removes a rule from the engine
	UnregisterRule(ruleID RuleID) error

	// GetRule retrieves a rule by ID
	GetRule(ruleID RuleID) (Rule, error)

	// ListRules returns all registered rules
	ListRules() []Rule
}

// Service provides a facade for policy operations
type Service interface {
	// GetPolicyEngine returns the policy evaluation engine
	GetPolicyEngine() PolicyEngine

	// GetZoneManager returns the trust zone manager
	GetZoneManager() ZoneManager

	// GetViolationHandler returns the violation handler
	GetViolationHandler() ViolationHandler

	// GetRuleFactory returns the rule factory
	GetRuleFactory() RuleFactory
}

// NewService creates a new policy service instance
func NewService() (Service, error) {
	// TODO: Implement service creation
	return nil, nil
}

// Common built-in rules

// SignatureVerificationRule verifies artifact signatures
type SignatureVerificationRule struct {
	// BaseRule contains common rule properties
	BaseRule

	// RequiredSigners lists identities that must sign
	RequiredSigners []string

	// MinimumSignatures is the minimum number of valid signatures required
	MinimumSignatures int
}

// ProvenanceVerificationRule verifies artifact provenance
type ProvenanceVerificationRule struct {
	// BaseRule contains common rule properties
	BaseRule

	// RequiredProvenanceTypes lists required provenance attestation types
	RequiredProvenanceTypes []string

	// TrustedBuilders lists trusted builder identities
	TrustedBuilders []string
}

// DependencyRule verifies artifact dependencies
type DependencyRule struct {
	// BaseRule contains common rule properties
	BaseRule

	// AllowedSources lists allowed dependency sources
	AllowedSources []string

	// BlockedDependencies lists prohibited dependencies
	BlockedDependencies []string

	// RequireVerifiedDependencies requires dependencies to be verified
	RequireVerifiedDependencies bool
}

// BaseRule implements common Rule functionality
type BaseRule struct {
	// id is the rule's unique identifier
	id RuleID

	// name is the rule's human-readable name
	name string

	// description explains the rule's purpose
	description string

	// severity indicates the rule's importance
	severity Severity

	// metadata contains additional rule information
	metadata map[string]string
}

// ID returns the rule's unique identifier
func (r BaseRule) ID() RuleID {
	return r.id
}

// Name returns the rule's human-readable name
func (r BaseRule) Name() string {
	return r.name
}

// Description returns a detailed explanation of the rule
func (r BaseRule) Description() string {
	return r.description
}

// Severity returns the rule's severity level
func (r BaseRule) Severity() Severity {
	return r.severity
}

// GetMetadata returns rule metadata
func (r BaseRule) GetMetadata() map[string]string {
	return r.metadata
}

