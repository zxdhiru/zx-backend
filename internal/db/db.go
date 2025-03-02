package db

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
	"github.com/zx/zx-backend/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

// Initialize initializes the database connection
func Initialize(cfg *config.Config) error {
	// First, try to create database if it doesn't exist
	createDBIfNotExists(cfg)

	// Connect to the database using the DSN from config
	var err error
	DB, err = gorm.Open(postgres.Open(cfg.GetDSN()), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	log.Println("Connected to database successfully")

	// Drop existing tables
	err = DB.Migrator().DropTable(
		&User{},
		&Session{},
		&WebAuthnCredential{},
		&OAuthClient{},
		&OAuthToken{},
		&OAuthAuthorizationCode{},
	)
	if err != nil {
		log.Printf("Warning: Failed to drop tables: %v", err)
	}

	// Run migrations to create tables
	err = DB.AutoMigrate(
		&User{},
		&Session{},
		&WebAuthnCredential{},
		&OAuthClient{},
		&OAuthToken{},
		&OAuthAuthorizationCode{},
	)
	if err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	log.Println("Database migrations completed successfully")
	return nil
}

// createDBIfNotExists creates the database if it doesn't exist
func createDBIfNotExists(cfg *config.Config) {
	// Connect to postgres database to create new database
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=postgres port=%s sslmode=%s",
		cfg.Database.Host,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Port,
		cfg.Database.SSLMode,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Printf("Warning: Failed to connect to postgres database: %v", err)
		return
	}
	defer db.Close()

	// Check if database exists
	var exists bool
	query := fmt.Sprintf("SELECT EXISTS(SELECT datname FROM pg_catalog.pg_database WHERE datname = '%s');", cfg.Database.Name)
	err = db.QueryRow(query).Scan(&exists)
	if err != nil {
		log.Printf("Warning: Failed to check if database exists: %v", err)
		return
	}

	// Create database if it doesn't exist
	if !exists {
		_, err = db.Exec(fmt.Sprintf("CREATE DATABASE %s;", cfg.Database.Name))
		if err != nil {
			log.Printf("Warning: Failed to create database: %v", err)
			return
		}
		log.Printf("Created database %s", cfg.Database.Name)
	}
}

// GetDB returns the database instance
func GetDB() *gorm.DB {
	return DB
}

// Close closes the database connection
func Close() error {
	if DB == nil {
		return nil
	}
	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
} 