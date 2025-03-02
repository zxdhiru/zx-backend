package auth

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/zx/zx-backend/config"
	"github.com/zx/zx-backend/internal/services/user"
)

type Handler struct {
	userService *user.Service
	config      *config.Config
}

type RegisterRequest struct {
	Username     string `json:"username"`
	Name         string `json:"name"`
	Password     string `json:"password"`
	MobileNumber string `json:"mobile_number"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Token string `json:"token"`
}

func NewHandler(userService *user.Service, cfg *config.Config) *Handler {
	return &Handler{
		userService: userService,
		config:      cfg,
	}
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Post("/register", h.Register)
	r.Post("/login", h.Login)
	r.Post("/logout", h.Logout)

	return r
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.Username == "" || req.Password == "" || req.MobileNumber == "" {
		http.Error(w, "Username, password, and mobile number are required", http.StatusBadRequest)
		return
	}

	// Create user
	newUser, err := h.userService.CreateUser(user.CreateUserInput{
		Username:     req.Username,
		Name:         req.Name,
		Password:     req.Password,
		MobileNumber: req.MobileNumber,
	})
	if err != nil {
		switch err {
		case user.ErrUsernameTaken:
			http.Error(w, "Username is already taken", http.StatusConflict)
		case user.ErrMobileNumberTaken:
			http.Error(w, "Mobile number is already taken", http.StatusConflict)
		default:
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":            newUser.ID,
		"username":      newUser.Username,
		"email":        newUser.Email,
		"name":         newUser.Name,
		"mobile_number": newUser.MobileNumber,
	})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Attempt login
	session, err := h.userService.Login(user.LoginInput{
		Username: req.Username,
		Password: req.Password,
	})
	if err != nil {
		switch err {
		case user.ErrUserNotFound, user.ErrInvalidPassword:
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		default:
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    session.SessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.config.Env == "production",
		SameSite: http.SameSiteStrictMode,
	})

	json.NewEncoder(w).Encode(AuthResponse{
		Token: session.SessionToken,
	})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, "No session found", http.StatusBadRequest)
		return
	}

	if err := h.userService.Logout(cookie.Value); err != nil {
		http.Error(w, "Failed to logout", http.StatusInternalServerError)
		return
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.config.Env == "production",
		SameSite: http.SameSiteStrictMode,
	})

	w.WriteHeader(http.StatusNoContent)
} 