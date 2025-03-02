package config

import (
	"fmt"
	"os"
	"time"

	"github.com/joho/godotenv"
)

// Config holds all configuration for the application
type Config struct {
	Env      string
	Database struct {
		Host     string
		Port     string
		User     string
		Password string
		Name     string
		SSLMode  string
	}
	Server struct {
		Port string
	}

	// JWT settings
	JWTSecret        string
	AccessTokenTTL   time.Duration
	RefreshTokenTTL  time.Duration

	// OAuth settings
	OAuthClientID     string
	OAuthClientSecret string
	OAuthRedirectURI  string
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (*Config, error) {
	// Load .env file if it exists
	godotenv.Load()

	cfg := &Config{}

	// Set environment
	cfg.Env = getEnv("ENV", "development")

	// Database configuration
	cfg.Database.Host = getEnv("DB_HOST", "localhost")
	cfg.Database.Port = getEnv("DB_PORT", "5432")
	cfg.Database.User = getEnv("DB_USER", "postgres")
	cfg.Database.Password = getEnv("DB_PASSWORD", "postgres")
	cfg.Database.Name = getEnv("DB_NAME", "zx_auth")
	cfg.Database.SSLMode = getEnv("DB_SSLMODE", "disable")

	// Server configuration
	cfg.Server.Port = getEnv("PORT", "3000")

	// JWT settings
	cfg.JWTSecret = getEnv("JWT_SECRET", "your-secret-key")
	cfg.AccessTokenTTL = time.Hour * 1 // 1 hour
	cfg.RefreshTokenTTL = time.Hour * 24 // 24 hours

	// OAuth settings
	cfg.OAuthClientID = getEnv("OAUTH_CLIENT_ID", "")
	cfg.OAuthClientSecret = getEnv("OAUTH_CLIENT_SECRET", "")
	cfg.OAuthRedirectURI = getEnv("OAUTH_REDIRECT_URI", "http://localhost:3000/oauth/callback")

	return cfg, nil
}

// getEnv retrieves an environment variable with a default value
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// GetDSN returns the database connection string
func (c *Config) GetDSN() string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.Database.Host,
		c.Database.Port,
		c.Database.User,
		c.Database.Password,
		c.Database.Name,
		c.Database.SSLMode,
	)
} 