package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"flag"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWT Claims structure
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Login page HTML template
var loginTemplate = template.Must(template.New("login").Parse(`
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h2>Login with JWT</h2>
    <form method="POST" action="/login">
        <label for="token">JWT Token:</label>
        <input type="text" id="token" name="token" required>
        <button type="submit">Login</button>
    </form>
</body>
</html>
`))

// Handler for the login page
func loginPageHandler(w http.ResponseWriter, r *http.Request, jwtSecret []byte) {
	if r.Method == http.MethodGet {
		loginTemplate.Execute(w, nil)
	} else if r.Method == http.MethodPost {
		token := r.FormValue("token")
		claims := &Claims{}

		// Parse and validate the JWT token
		parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))

		if err != nil || !parsedToken.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Token is valid, set a session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    token, // Use the token as session token for simplicity
			Expires:  time.Now().Add(1 * time.Hour),
			HttpOnly: true,
			Secure:   false, // Change to true if using HTTPS
			Path:     "/",
		})

		// Redirect to the home page or protected resource
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// Middleware to check JWT in cookies
func authenticate(next http.Handler, jwtSecret []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			// Redirect to login if no session cookie
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		token := cookie.Value
		claims := &Claims{}
		parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))

		if err != nil || !parsedToken.Valid {
			// Redirect to login if token is invalid
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// Token is valid, continue to the requested resource
		next.ServeHTTP(w, r)
	})
}

func main() {
	// Command-line arguments
	staticDir := flag.String("static-dir", "./static", "Directory to serve static files from")
	port := flag.String("port", "8080", "Port to listen on")
	flag.Parse()

	// Environment variable for JWT secret
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	// Static file server
	staticFileServer := http.FileServer(http.Dir(*staticDir))

	// Routes
	http.Handle("/static/", http.StripPrefix("/static", authenticate(staticFileServer, []byte(jwtSecret))))
	http.Handle("/login", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginPageHandler(w, r, []byte(jwtSecret))
	}))
	http.Handle("/", authenticate(http.HandlerFunc(homeHandler), []byte(jwtSecret)))

	fmt.Printf("Server is running on port %s\n", *port)
	log.Fatal(http.ListenAndServe(":" + *port, nil))
}

// Handler for the home page (or other protected resources)
func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>Home</title>
	</head>
	<body>
		<h1>Welcome to the protected resource</h1>
		<a href="/static/file.txt">Access static file</a>
	</body>
	</html>
	`))
}

