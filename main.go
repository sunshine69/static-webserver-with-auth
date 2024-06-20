package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go/v4"
)

// Struct for JWT claims
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// Middleware function to authenticate JWT
func authenticate(next http.Handler, jwtSecret []byte) http.Handler {
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
	// Define flags for static directory path, JWT secret environment variable, and server port
	var staticDir string
	var jwtSecret string
	var port string

	flag.StringVar(&staticDir, "static-dir", "./static", "Path to the static directory")
	flag.StringVar(&jwtSecret, "jwt-secret", "", "JWT secret key (environment variable)")
	flag.StringVar(&port, "port", "8080", "Port for the server to listen on")

	flag.Parse()

	// Validate the static directory path
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		log.Fatalf("Static directory '%s' does not exist", staticDir)
	}

	// Validate JWT secret
	if jwtSecret == "" {
		log.Fatal("JWT secret is not provided")
	}

	// Convert JWT secret to []byte
	jwtSecretBytes := []byte(jwtSecret)

	// Create a file server for the static directory
	fs := http.FileServer(http.Dir(staticDir))

	// Handle requests to serve static files with authentication middleware
	http.Handle("/", authenticate(fs, jwtSecretBytes))

	// Start the server
	addr := ":" + port
	fmt.Printf("Server listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

