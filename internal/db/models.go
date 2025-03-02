package db

import (
	"time"

	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	gorm.Model
	Username          string `gorm:"uniqueIndex;not null"`
	Email             string `gorm:"uniqueIndex;not null"`
	MobileNumber      string `gorm:"uniqueIndex;not null"`
	Name              string
	Password          string `gorm:"not null"`
	WebAuthnCredsID   []WebAuthnCredential `gorm:"foreignKey:UserID"`
	OAuthTokens       []OAuthToken         `gorm:"foreignKey:UserID"`
	LastLoginAt       *time.Time
}

// WebAuthnCredential represents a WebAuthn credential for a user
type WebAuthnCredential struct {
	gorm.Model
	UserID              uint   `gorm:"not null"`
	CredentialID        []byte `gorm:"uniqueIndex;not null"`
	PublicKey          []byte `gorm:"not null"`
	AttestationType    string
	AAGUID             []byte
	SignCount          uint32
	CredentialName     string
	LastUsedAt         *time.Time
}

// OAuthClient represents a registered OAuth client application
type OAuthClient struct {
	gorm.Model
	ClientID     string `gorm:"uniqueIndex;not null"`
	ClientSecret string `gorm:"not null"`
	Name         string `gorm:"not null"`
	RedirectURIs string `gorm:"not null"` // Comma-separated list of allowed redirect URIs
	GrantTypes   string `gorm:"not null"` // Comma-separated list of allowed grant types
	Scopes       string // Comma-separated list of allowed scopes
	IsConfidential bool `gorm:"default:true"`
	CreatedByUserID uint
	Status         string `gorm:"default:'active'"` // active, suspended, revoked
}

// OAuthToken represents an OAuth token issued to a client
type OAuthToken struct {
	gorm.Model
	UserID           uint   `gorm:"not null"`
	ClientID         string `gorm:"not null"`
	AccessToken      string `gorm:"uniqueIndex;not null"`
	RefreshToken     string `gorm:"uniqueIndex"`
	TokenType        string `gorm:"default:'Bearer'"`
	Scope           string
	ExpiresAt       time.Time
	RefreshExpiresAt *time.Time
	RevokedAt       *time.Time
	IPAddress       string
	UserAgent       string
}

// OAuthAuthorizationCode represents an OAuth authorization code
type OAuthAuthorizationCode struct {
	gorm.Model
	UserID      uint   `gorm:"not null"`
	ClientID    string `gorm:"not null"`
	Code        string `gorm:"uniqueIndex;not null"`
	RedirectURI string `gorm:"not null"`
	Scope       string
	ExpiresAt   time.Time
	Used        bool      `gorm:"default:false"`
	UsedAt      *time.Time
}

// Session represents a user session
type Session struct {
	gorm.Model
	UserID         uint      `gorm:"not null"`
	SessionToken   string    `gorm:"uniqueIndex;not null"`
	ExpiresAt      time.Time `gorm:"not null"`
	IPAddress      string
	UserAgent      string
	LastActivityAt time.Time
	RevokedAt      *time.Time
} 