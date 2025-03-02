package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/zx/zx-backend/internal/services/user"
)

type contextKey string

const (
	UserContextKey  contextKey = "user"
	TokenContextKey contextKey = "token"
	ClientIDKey    contextKey = "clientID"
	ClientSecretKey contextKey = "clientSecret"
)

// AuthMiddleware authenticates requests using the session token
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get session token from cookie
		cookie, err := r.Cookie("session")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get user service
		userService := user.NewService(nil) // TODO: Pass config from app context

		// Validate session and get user
		user, err := userService.ValidateSession(cookie.Value)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Add user to request context
		ctx := context.WithValue(r.Context(), UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// BearerAuth middleware checks for a valid Bearer token
func BearerAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the Authorization header
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "Missing authorization header", http.StatusUnauthorized)
			return
		}

		// Check if it's a Bearer token
		parts := strings.Split(auth, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		// Store the token in the context
		ctx := context.WithValue(r.Context(), TokenContextKey, parts[1])
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ClientAuth middleware checks for valid client credentials
func ClientAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID := r.Header.Get("X-Client-ID")
		clientSecret := r.Header.Get("X-Client-Secret")

		if clientID == "" || clientSecret == "" {
			http.Error(w, "Missing client credentials", http.StatusUnauthorized)
			return
		}

		// Store the client credentials in the context
		ctx := context.WithValue(r.Context(), ClientIDKey, clientID)
		ctx = context.WithValue(ctx, ClientSecretKey, clientSecret)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
} 