package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

// Define a secret key used to sign the JWTs (should be stored securely in production)
var jwtSecret = []byte("secret-key-for-jwt")

// Struct for JWT claims
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// Middleware function to authenticate JWT
func authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the token from the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header is required", http.StatusUnauthorized)
			return
		}

		// Extract the JWT token from the Authorization header
		authParts := strings.Split(authHeader, " ")
		if len(authParts) != 2 || authParts[0] != "Bearer" {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		tokenString := authParts[1]

		// Parse the token
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Verify the token is valid
		if !token.Valid {
			http.Error(w, "Token is not valid", http.StatusUnauthorized)
			return
		}

		// If the token is valid, continue to the next handler
		next.ServeHTTP(w, r)
	})
}

func main() {
	// Create a file server for the "static" directory
	fs := http.FileServer(http.Dir("./static"))

	// Handle requests to serve static files with authentication middleware
	http.Handle("/", authenticate(fs))

	// Start the server
	port := ":8080"
	fmt.Printf("Server listening on port %s\n", port)
	log.Fatal(http.ListenAndServe(port, nil))
}

