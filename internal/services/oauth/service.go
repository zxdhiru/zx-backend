package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zx/zx-backend/config"
	"github.com/zx/zx-backend/internal/db"
)

var (
	ErrInvalidClient      = errors.New("invalid client credentials")
	ErrInvalidCode        = errors.New("invalid authorization code")
	ErrInvalidToken       = errors.New("invalid token")
	ErrInvalidGrant       = errors.New("invalid grant type")
	ErrInvalidRedirectURI = errors.New("invalid redirect URI")
)

type Service struct {
	config *config.Config
}

type AuthorizeInput struct {
	ClientID     string
	RedirectURI  string
	Scope        string
	State        string
	SessionToken string
}

type TokenInput struct {
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
}

type RefreshInput struct {
	RefreshToken string
	ClientID     string
	ClientSecret string
}

type RevokeInput struct {
	Token        string
	ClientID     string
	ClientSecret string
}

type Token struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func NewService(cfg *config.Config) *Service {
	return &Service{
		config: cfg,
	}
}

// CreateAuthorizationCode creates a new authorization code
func (s *Service) CreateAuthorizationCode(userID uint, clientID, redirectURI, scope string) (string, error) {
	// Validate client
	var client db.OAuthClient
	if err := db.DB.Where("client_id = ? AND status = ?", clientID, "active").First(&client).Error; err != nil {
		return "", ErrInvalidClient
	}

	// Validate redirect URI
	if client.RedirectURIs != redirectURI {
		return "", ErrInvalidRedirectURI
	}

	// Generate code
	code := generateRandomString(32)

	// Create authorization code
	authCode := &db.OAuthAuthorizationCode{
		UserID:      userID,
		ClientID:    clientID,
		Code:        code,
		RedirectURI: redirectURI,
		Scope:       scope,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}

	if err := db.DB.Create(authCode).Error; err != nil {
		return "", fmt.Errorf("failed to create authorization code: %w", err)
	}

	return code, nil
}

// ExchangeAuthorizationCode exchanges an authorization code for tokens
func (s *Service) ExchangeAuthorizationCode(code, redirectURI, clientID, clientSecret string) (*Token, error) {
	// Validate client
	var client db.OAuthClient
	if err := db.DB.Where("client_id = ? AND client_secret = ? AND status = ?",
		clientID, clientSecret, "active").First(&client).Error; err != nil {
		return nil, ErrInvalidClient
	}

	// Find and validate authorization code
	var authCode db.OAuthAuthorizationCode
	if err := db.DB.Where("code = ? AND client_id = ? AND redirect_uri = ? AND used = ? AND expires_at > ?",
		code, clientID, redirectURI, false, time.Now()).First(&authCode).Error; err != nil {
		return nil, ErrInvalidCode
	}

	// Mark code as used
	now := time.Now()
	authCode.Used = true
	authCode.UsedAt = &now
	if err := db.DB.Save(&authCode).Error; err != nil {
		return nil, fmt.Errorf("failed to update authorization code: %w", err)
	}

	// Generate tokens
	accessToken := generateRandomString(32)
	refreshToken := generateRandomString(32)

	// Create OAuth token
	token := &db.OAuthToken{
		UserID:           authCode.UserID,
		ClientID:         clientID,
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		TokenType:        "Bearer",
		Scope:           authCode.Scope,
		ExpiresAt:       time.Now().Add(s.config.AccessTokenTTL),
		RefreshExpiresAt: &now,
	}

	if err := db.DB.Create(token).Error; err != nil {
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	return &Token{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.config.AccessTokenTTL.Seconds()),
		RefreshToken: refreshToken,
		Scope:        authCode.Scope,
	}, nil
}

// RefreshAccessToken refreshes an access token using a refresh token
func (s *Service) RefreshAccessToken(refreshToken, clientID, clientSecret string) (*Token, error) {
	// Validate client
	var client db.OAuthClient
	if err := db.DB.Where("client_id = ? AND client_secret = ? AND status = ?",
		clientID, clientSecret, "active").First(&client).Error; err != nil {
		return nil, ErrInvalidClient
	}

	// Find and validate refresh token
	var oldToken db.OAuthToken
	if err := db.DB.Where("refresh_token = ? AND client_id = ? AND revoked_at IS NULL AND refresh_expires_at > ?",
		refreshToken, clientID, time.Now()).First(&oldToken).Error; err != nil {
		return nil, ErrInvalidToken
	}

	// Generate new tokens
	accessToken := generateRandomString(32)
	newRefreshToken := generateRandomString(32)
	now := time.Now()

	// Create new token
	token := &db.OAuthToken{
		UserID:           oldToken.UserID,
		ClientID:         clientID,
		AccessToken:      accessToken,
		RefreshToken:     newRefreshToken,
		TokenType:        "Bearer",
		Scope:           oldToken.Scope,
		ExpiresAt:       now.Add(s.config.AccessTokenTTL),
		RefreshExpiresAt: &now,
	}

	if err := db.DB.Create(token).Error; err != nil {
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	// Revoke old token
	oldToken.RevokedAt = &now
	if err := db.DB.Save(&oldToken).Error; err != nil {
		return nil, fmt.Errorf("failed to revoke old token: %w", err)
	}

	return &Token{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.config.AccessTokenTTL.Seconds()),
		RefreshToken: newRefreshToken,
		Scope:        oldToken.Scope,
	}, nil
}

// RevokeToken revokes an access token or refresh token
func (s *Service) RevokeToken(token, clientID, clientSecret string) error {
	// Validate client
	var client db.OAuthClient
	if err := db.DB.Where("client_id = ? AND client_secret = ? AND status = ?",
		clientID, clientSecret, "active").First(&client).Error; err != nil {
		return ErrInvalidClient
	}

	// Find and revoke token
	now := time.Now()
	result := db.DB.Model(&db.OAuthToken{}).
		Where("(access_token = ? OR refresh_token = ?) AND client_id = ? AND revoked_at IS NULL",
			token, token, clientID).
		Update("revoked_at", now)

	if result.Error != nil {
		return fmt.Errorf("failed to revoke token: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrInvalidToken
	}

	return nil
}

// ValidateAccessToken validates an access token and returns the associated user ID
func (s *Service) ValidateAccessToken(accessToken string) (uint, error) {
	var token db.OAuthToken

	if err := db.DB.Where("access_token = ? AND expires_at > ? AND revoked_at IS NULL",
		accessToken, time.Now()).First(&token).Error; err != nil {
		return 0, fmt.Errorf("invalid access token")
	}

	return token.UserID, nil
}

// Helper functions

func (s *Service) generateAccessToken(userID uint, clientID, scope string) (string, error) {
	claims := jwt.MapClaims{
		"sub":   userID,
		"aud":   clientID,
		"scope": scope,
		"exp":   time.Now().Add(s.config.AccessTokenTTL).Unix(),
		"iat":   time.Now().Unix(),
		"iss":   "zx-auth-service",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWTSecret))
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:length]
} 