package user

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/zx/zx-backend/internal/db"
	"github.com/zx/zx-backend/internal/middleware"
	"github.com/zx/zx-backend/internal/services/user"
)

type Handler struct {
	service *user.Service
}

func NewHandler(service *user.Service) *Handler {
	return &Handler{
		service: service,
	}
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()

	// Protected routes (require authentication)
	r.Group(func(r chi.Router) {
		r.Use(middleware.AuthMiddleware)
		r.Get("/profile", h.GetProfile)
		r.Put("/profile", h.UpdateProfile)
		r.Delete("/profile", h.DeleteProfile)
	})

	return r
}

type UpdateProfileRequest struct {
	Name         string `json:"name"`
	MobileNumber string `json:"mobile_number"`
}

func (h *Handler) GetProfile(w http.ResponseWriter, r *http.Request) {
	// Get user from context (set by auth middleware)
	user := r.Context().Value(middleware.UserContextKey).(*db.User)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":            user.ID,
		"username":      user.Username,
		"name":         user.Name,
		"mobile_number": user.MobileNumber,
		"email":        user.Email,
	})
}

func (h *Handler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	var req UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get user from context
	currentUser := r.Context().Value(middleware.UserContextKey).(*db.User)

	// Update user profile
	updates := make(map[string]interface{})
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.MobileNumber != "" {
		// Check if mobile number is already taken
		if err := h.service.CheckMobileNumberAvailable(req.MobileNumber, currentUser.ID); err != nil {
			if err == user.ErrMobileNumberTaken {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		updates["mobile_number"] = req.MobileNumber
	}

	if len(updates) == 0 {
		http.Error(w, "No updates provided", http.StatusBadRequest)
		return
	}

	updatedUser, err := h.service.UpdateUser(currentUser.ID, updates)
	if err != nil {
		http.Error(w, "Failed to update profile", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":            updatedUser.ID,
		"username":      updatedUser.Username,
		"name":         updatedUser.Name,
		"mobile_number": updatedUser.MobileNumber,
		"email":        updatedUser.Email,
	})
}

func (h *Handler) DeleteProfile(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	user := r.Context().Value(middleware.UserContextKey).(*db.User)

	if err := h.service.DeleteUser(user.ID); err != nil {
		http.Error(w, "Failed to delete profile", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
} 