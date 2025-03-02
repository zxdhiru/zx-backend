package oauth

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/zx/zx-backend/config"
	"github.com/zx/zx-backend/internal/services/oauth"
	"github.com/zx/zx-backend/internal/services/user"
)

type Handler struct {
	service *oauth.Service
	config  *config.Config
}

func NewHandler(service *oauth.Service, cfg *config.Config) *Handler {
	return &Handler{
		service: service,
		config:  cfg,
	}
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/authorize", h.Authorize)
	r.Post("/token", h.Token)
	r.Post("/revoke", h.Revoke)

	return r
}

func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	// Get query parameters
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	responseType := r.URL.Query().Get("response_type")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")

	// Validate request
	if clientID == "" || redirectURI == "" || responseType != "code" {
		http.Error(w, "Invalid request parameters", http.StatusBadRequest)
		return
	}

	// Get user from session
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get user service and validate session
	userService := user.NewService(h.config)
	currentUser, err := userService.ValidateSession(cookie.Value)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Generate authorization code
	code, err := h.service.CreateAuthorizationCode(currentUser.ID, clientID, redirectURI, scope)
	if err != nil {
		http.Error(w, "Failed to create authorization code", http.StatusInternalServerError)
		return
	}

	// Redirect back to client with code
	redirectURL := redirectURI + "?code=" + code
	if state != "" {
		redirectURL += "&state=" + state
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get form parameters
	grantType := r.Form.Get("grant_type")
	code := r.Form.Get("code")
	redirectURI := r.Form.Get("redirect_uri")
	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	refreshToken := r.Form.Get("refresh_token")

	var token *oauth.Token
	var err error

	switch grantType {
	case "authorization_code":
		if code == "" || redirectURI == "" || clientID == "" || clientSecret == "" {
			http.Error(w, "Missing required parameters", http.StatusBadRequest)
			return
		}
		token, err = h.service.ExchangeAuthorizationCode(code, redirectURI, clientID, clientSecret)
	case "refresh_token":
		if refreshToken == "" || clientID == "" || clientSecret == "" {
			http.Error(w, "Missing required parameters", http.StatusBadRequest)
			return
		}
		token, err = h.service.RefreshAccessToken(refreshToken, clientID, clientSecret)
	default:
		http.Error(w, "Unsupported grant type", http.StatusBadRequest)
		return
	}

	if err != nil {
		switch err {
		case oauth.ErrInvalidClient:
			http.Error(w, "Invalid client credentials", http.StatusUnauthorized)
		case oauth.ErrInvalidCode:
			http.Error(w, "Invalid authorization code", http.StatusBadRequest)
		case oauth.ErrInvalidToken:
			http.Error(w, "Invalid token", http.StatusBadRequest)
		default:
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(token)
}

func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get form parameters
	token := r.Form.Get("token")
	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")

	if token == "" || clientID == "" || clientSecret == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	if err := h.service.RevokeToken(token, clientID, clientSecret); err != nil {
		switch err {
		case oauth.ErrInvalidClient:
			http.Error(w, "Invalid client credentials", http.StatusUnauthorized)
		case oauth.ErrInvalidToken:
			http.Error(w, "Invalid token", http.StatusBadRequest)
		default:
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
} 