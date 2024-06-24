package main

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
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

var cookieName, authType, queryParamKey string

// Path to the web root dir. This will be relative path to the current root; like ./static. The route path will be absolute like /static
// and then be stripped off. This can be an absolute path though started with / but the route will be the same exactly absolute path
// No slash / at the end
var webRoot string

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
			Name:     cookieName,
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
		var token string
		switch authType {
		case "jwt-cookie":
			cookie, err := r.Cookie(cookieName)
			if err != nil {
				// Redirect to login if no session cookie
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			token = cookie.Value
		case "jwt-query-param":
			token = r.URL.Query().Get(queryParamKey)
		case "bypass":
			next.ServeHTTP(w, r)
		}

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
	staticDir := flag.String("web-root", "./static", "Directory to serve static files from")
	port := flag.String("port", "8080", "Port to listen on")

	flag.Usage = func() {
		flag.PrintDefaults()
		fmt.Println(`           
							***** static web server with jwt auth *****
		This web server serves static files and protected with jwt auth. Apart from command flags the enn vars below will override it
		- JWT_SECRET - The secret to validate the jwt token
		- SESSION_COOKIE_NAME - the session cookie name used to get the jwt token. Default is statis_web_srv_session
		- WEB_ROOT - The directory path to serve files from. Can be relative path to the current dir, or absolute path.
		  The html path will be the same without dot if it is relative. Override cmd flag 'web-root'
		- PORT - http port to listen. Default 8080.
		- AUTH_TYPE - default is jwt-cookie. Can be:
		  - 'jwt-cookie' - store and get the jwt token from session cookie
		  - 'jwt-query-param' - Get the jwt from query parameter. In this case need to provide a env var. Also there is no login helper for this case.
		    - QUERY_PARAM_KEY - The parameter key. Default is 'access_token'; that is the url is like https://<domain>/path?access_token=<jwt-token-string>
		`)
	}
	flag.Parse()

	// Environment variable for JWT secret
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	cookieName = os.Getenv("SESSION_COOKIE_NAME")
	if cookieName == "" {
		cookieName = "statis_web_srv_session"
	}

	listenPort := os.Getenv("PORT")
	if listenPort == "" {
		listenPort = *port
	}

	authType = os.Getenv("AUTH_TYPE") // jwt-cookie, jwt-query-param
	if authType == "" {
		authType = "jwt-cookie"
	}

	queryParamKey = os.Getenv("QUERY_PARAM_KEY")
	if queryParamKey == "" {
		queryParamKey = "access_token"
	}

	// Static file server
	webRoot = os.Getenv("WEB_ROOT")
	if webRoot == "" {
		webRoot = *staticDir
	}

	staticFileServer := http.FileServer(http.Dir(webRoot))

	var staticRoutePath, stripPrefix string
	if strings.HasPrefix(webRoot, ".") {
		stripPrefix = strings.TrimPrefix(webRoot, ".")
		staticRoutePath = stripPrefix + "/"
	} else {
		staticRoutePath = webRoot + "/"
		stripPrefix = webRoot
	}

	// Routes
	http.Handle(staticRoutePath, http.StripPrefix(stripPrefix, authenticate(staticFileServer, []byte(jwtSecret))))
	http.Handle("/login", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginPageHandler(w, r, []byte(jwtSecret))
	}))
	http.Handle("/", authenticate(http.HandlerFunc(homeHandler), []byte(jwtSecret)))

	fmt.Printf("Server is running on port %s\n", listenPort)
	log.Fatal(http.ListenAndServe(":"+listenPort, nil))
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
