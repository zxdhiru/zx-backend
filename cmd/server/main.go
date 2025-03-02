package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/zx/zx-backend/config"
	"github.com/zx/zx-backend/internal/db"
	"github.com/zx/zx-backend/internal/handlers/auth"
	"github.com/zx/zx-backend/internal/handlers/oauth"
	oauthService "github.com/zx/zx-backend/internal/services/oauth"
	"github.com/zx/zx-backend/internal/services/user"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database
	if err := db.Initialize(cfg); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Initialize services
	userService := user.NewService(cfg)
	oauthSvc := oauthService.NewService(cfg)

	// Initialize handlers
	authHandler := auth.NewHandler(userService, cfg)
	oauthHandler := oauth.NewHandler(oauthSvc, cfg)

	// Create router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Mount routes
	r.Mount("/auth", authHandler.Routes())
	r.Mount("/oauth", oauthHandler.Routes())

	// Start server
	addr := fmt.Sprintf(":%s", cfg.Server.Port)
	log.Printf("Starting server on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
} 