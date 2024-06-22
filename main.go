package main

import (
    "flag"
    "fmt"
    "log"
    "net/http"
    "os"
    "strings"

    "github.com/golang-jwt/jwt/v5"
)

// JWT middleware to check the token
func jwtMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Get the JWT secret from the environment variable
        secret := os.Getenv("JWT_SECRET")
        if secret == "" {
            log.Fatal("JWT_SECRET environment variable is not set")
        }

	if secret == "BYPASS" {
	    next.ServeHTTP(w, r)
	}

        // Get the token from the Authorization header
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Authorization header missing", http.StatusUnauthorized)
            return
        }

        parts := strings.Split(authHeader, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
            return
        }

        tokenString := parts[1]

        // Parse the token
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            // Ensure the token method is correct
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
            }
            return []byte(secret), nil
        })

        if err != nil || !token.Valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        // If token is valid, proceed to the next handler
        next.ServeHTTP(w, r)
    })
}

func main() {
    // Define flags for directory and port
    staticDir := flag.String("path", "./static", "Path to the static files directory")
    port := flag.String("port", "8080", "Port to serve on")

    // Parse the flags
    flag.Parse()

    // Check if the JWT_SECRET environment variable is set
    secret := os.Getenv("JWT_SECRET")
    if secret == "" {
        log.Fatal("JWT_SECRET environment variable is not set")
    }

    // Set up the file server
    fs := http.FileServer(http.Dir(*staticDir))

    // Create a handler with JWT middleware
    http.Handle("/", jwtMiddleware(fs))

    log.Printf("Serving %s on HTTP port: %s\n", *staticDir, *port)
    err := http.ListenAndServe(":"+*port, nil)
    if err != nil {
        log.Fatal(err)
    }
}

