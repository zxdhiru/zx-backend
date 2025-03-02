package user

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/zx/zx-backend/config"
	"github.com/zx/zx-backend/internal/db"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUsernameTaken     = errors.New("username already taken")
	ErrMobileNumberTaken = errors.New("mobile number already taken")
	ErrInvalidPassword   = errors.New("invalid password")
)

type Service struct {
	config *config.Config
}

type CreateUserInput struct {
	Username     string
	Name         string
	Password     string
	MobileNumber string
}

type LoginInput struct {
	Username string
	Password string
}

func NewService(cfg *config.Config) *Service {
	return &Service{
		config: cfg,
	}
}

// CreateUser creates a new user account
func (s *Service) CreateUser(input CreateUserInput) (*db.User, error) {
	// Check if username is already taken
	var existingUser db.User
	if err := db.DB.Where("username = ?", input.Username).First(&existingUser).Error; err == nil {
		return nil, ErrUsernameTaken
	}

	// Check if mobile number is already taken
	if err := db.DB.Where("mobile_number = ?", input.MobileNumber).First(&existingUser).Error; err == nil {
		return nil, ErrMobileNumberTaken
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Generate email from username
	email := fmt.Sprintf("%s@zx.com", input.Username)

	// Create user
	user := &db.User{
		Username:     input.Username,
		Email:        email,
		MobileNumber: input.MobileNumber,
		Name:         input.Name,
		Password:     string(hashedPassword),
	}

	if err := db.DB.Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

// Login authenticates a user and creates a session
func (s *Service) Login(input LoginInput) (*db.Session, error) {
	// Find user by username
	var user db.User
	if err := db.DB.Where("username = ?", input.Username).First(&user).Error; err != nil {
		return nil, ErrUserNotFound
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		return nil, ErrInvalidPassword
	}

	// Create session
	sessionToken := generateRandomString(32)
	session := &db.Session{
		UserID:         user.ID,
		SessionToken:   sessionToken,
		ExpiresAt:      time.Now().Add(24 * time.Hour), // Sessions expire in 24 hours
		LastActivityAt: time.Now(),
	}

	if err := db.DB.Create(session).Error; err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Update last login time
	now := time.Now()
	user.LastLoginAt = &now
	if err := db.DB.Save(&user).Error; err != nil {
		return nil, fmt.Errorf("failed to update last login time: %w", err)
	}

	return session, nil
}

// GetUserByID retrieves a user by their ID
func (s *Service) GetUserByID(id uint) (*db.User, error) {
	var user db.User
	if err := db.DB.First(&user, id).Error; err != nil {
		return nil, ErrUserNotFound
	}
	return &user, nil
}

// ValidateSession validates a session token and returns the associated user
func (s *Service) ValidateSession(sessionToken string) (*db.User, error) {
	var session db.Session
	if err := db.DB.Where("session_token = ? AND expires_at > ? AND revoked_at IS NULL",
		sessionToken, time.Now()).First(&session).Error; err != nil {
		return nil, fmt.Errorf("invalid session")
	}

	// Update last activity time
	session.LastActivityAt = time.Now()
	if err := db.DB.Save(&session).Error; err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	return s.GetUserByID(session.UserID)
}

// Logout invalidates a session
func (s *Service) Logout(sessionToken string) error {
	now := time.Now()
	result := db.DB.Model(&db.Session{}).
		Where("session_token = ? AND revoked_at IS NULL", sessionToken).
		Update("revoked_at", &now)

	if result.Error != nil {
		return fmt.Errorf("failed to revoke session: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("session not found or already revoked")
	}

	return nil
}

// CheckMobileNumberAvailable checks if a mobile number is available for use
func (s *Service) CheckMobileNumberAvailable(mobileNumber string, excludeUserID uint) error {
	var existingUser db.User
	err := db.DB.Where("mobile_number = ? AND id != ?", mobileNumber, excludeUserID).First(&existingUser).Error
	if err == nil {
		return ErrMobileNumberTaken
	}
	return nil
}

// UpdateUser updates a user's profile
func (s *Service) UpdateUser(userID uint, updates map[string]interface{}) (*db.User, error) {
	var user db.User
	if err := db.DB.First(&user, userID).Error; err != nil {
		return nil, ErrUserNotFound
	}

	if err := db.DB.Model(&user).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return &user, nil
}

// DeleteUser deletes a user's account
func (s *Service) DeleteUser(userID uint) error {
	result := db.DB.Delete(&db.User{}, userID)
	if result.Error != nil {
		return fmt.Errorf("failed to delete user: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrUserNotFound
	}
	return nil
}

// Helper functions

func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:length]
} 