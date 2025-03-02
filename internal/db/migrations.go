package db

import "log"

// runMigrations runs all database migrations
func runMigrations() error {
	log.Println("Running database migrations...")

	// Auto-migrate all models
	// This will create tables if they don't exist and update existing tables
	// to match the model definitions
	err := DB.AutoMigrate(
		&User{},
		&WebAuthnCredential{},
		&OAuthClient{},
		&OAuthToken{},
		&OAuthAuthorizationCode{},
		&Session{},
	)
	if err != nil {
		return err
	}

	log.Println("Database migrations completed successfully")
	return nil
}

// rollbackMigrations rolls back all migrations (for testing purposes)
func rollbackMigrations() error {
	log.Println("Rolling back database migrations...")

	// Drop all tables in reverse order to handle foreign key constraints
	err := DB.Migrator().DropTable(
		&Session{},
		&OAuthAuthorizationCode{},
		&OAuthToken{},
		&OAuthClient{},
		&WebAuthnCredential{},
		&User{},
	)
	if err != nil {
		return err
	}

	log.Println("Database migrations rolled back successfully")
	return nil
} 