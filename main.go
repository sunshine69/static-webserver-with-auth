package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
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
    <form method="POST" action="{{ .loginPath }}">
        <label for="token">JWT Token:</label>
        <input type="text" id="token" name="token" required>
        <button type="submit">Login</button>
    </form>
</body>
</html>
`))

var (
	jwtSecret                           []byte
	signingMethod                       string
	rsaPubKey                           *rsa.PublicKey
	jwtParserOptionsLookup              map[string]jwt.ParserOption
	cookieName, authType, queryParamKey string
	secureCookie                        bool
	cookieLastDuration                  time.Duration

	// Path to the web root dir. This will be relative path to the current root; like ./static. The route path will be absolute like /static
	// and then be stripped off. This can be an absolute path though started with / but the route will be the same exactly absolute path
	// No slash / at the end
	webRoot                                                                  string
	publicRoot                                                               string
	loginPath                                                                string
	pathBase                                                                 string
	loginURL                                                                 string
	privateRoutePath, publicRoutePath, stripPrefixPrivate, stripPrefixPublic string
)

func ParseJWTToken(token string, claims *Claims) (parsedToken *jwt.Token, err error) {
	switch signingMethod {
	case "HS256":
		parsedToken, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		}, jwtParserOptionsLookup[signingMethod])

	case "RS256":
		parsedToken, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return rsaPubKey, nil
		}, jwtParserOptionsLookup[signingMethod])
	}
	return
}

// Handler for the login page
func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		loginTemplate.Execute(w, map[string]interface{}{"loginPath": loginPath})
	case http.MethodPost:
		token := r.FormValue("token")
		claims := &Claims{}

		// Parse and validate the JWT token
		parsedToken, err := ParseJWTToken(token, claims)

		if err != nil || !parsedToken.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Token is valid, set a session cookie

		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    token, // Use the token as session token for simplicity
			Expires:  time.Now().Add(cookieLastDuration),
			HttpOnly: true,
			Secure:   secureCookie,
			Path:     privateRoutePath,
		})

		// Redirect to the home page or protected resource
		http.Redirect(w, r, privateRoutePath, http.StatusFound)
	}
}

// Middleware to check JWT in cookies
func authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string
		switch authType {
		case "jwt-cookie":
			cookie, err := r.Cookie(cookieName)
			if err != nil {
				// Redirect to login if no session cookie
				http.Redirect(w, r, loginPath, http.StatusFound)
				return
			}
			token = cookie.Value
		case "jwt-query-param":
			token = r.URL.Query().Get(queryParamKey)
		case "auto":
			cookie, err := r.Cookie(cookieName)
			if err != nil {
				token = r.URL.Query().Get(queryParamKey)
			} else {
				token = cookie.Value
			}
			if token == "" {
				// Redirect to login if all hopes lost
				http.Redirect(w, r, loginPath, http.StatusFound)
				return
			}
		case "bypass":
			next.ServeHTTP(w, r)
			return
		}

		claims := &Claims{}
		parsedToken, err := ParseJWTToken(token, claims)

		if err != nil || !parsedToken.Valid {
			// Redirect to login if token is invalid
			http.Redirect(w, r, loginPath, http.StatusFound)
			return
		}

		// Token is valid, set a session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    token, // Use the token as session token for simplicity
			Expires:  time.Now().Add(cookieLastDuration),
			HttpOnly: true,
			Secure:   secureCookie,
			Path:     privateRoutePath,
		})
		// Token is valid, continue to the requested resource
		next.ServeHTTP(w, r)
	})
}

func main() {
	jwtParserOptionsLookup = map[string]jwt.ParserOption{ // Add more options here if u want to support more than these
		"HS256": jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
		"RS256": jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Name}),
	}
	// Command-line arguments
	staticDir := flag.String("web-root", "", "Directory to serve static files from")
	publicDir := flag.String("public-root", "", "Public Directory to serve static files from. Optional")
	port := flag.String("port", "8080", "Port to listen on")
	flag.StringVar(&signingMethod, "jwt-sign", "HS256", "JWT Signing method. Value can be HS256 (HMAC using SHA256) or RS256 (RSA using SHA256)")
	rsaPubKeyPath := flag.String("rsa-public-key", "", "File path - RSA public key used when signing method is RS256")

	flag.Usage = func() {
		flag.PrintDefaults()
		fmt.Println(`
							***** static web server with jwt auth *****
		This web server serves static files and protected with jwt auth. Apart from command flags the env vars below will override it

		- JWT_SECRET - The secret to validate the jwt token
		- JWT_SIGN - override option --jwt-sign with same value.
		- RSA_PUBLIC_KEY - override option --rsa-public-key
		- SESSION_COOKIE_NAME - the session cookie name used to get the jwt token. Default is statis_web_srv_session

		- WEB_ROOT - The protected directory path to serve files from. Can be relative path to the current working dir, or absolute path.
		  Pay attention to extra slashes for WEB_ROOT and PUBLIC_ROOT.
		  The html path will be the same without dot if it is relative. Override cmd flag '-web-root'.

		- PUBLIC_ROOT - The non protected directory path to serve files from. Can be relative path to the current dir, or absolute path.

		  Both WEB_ROOT and PUBLIC_ROOT, If it is absolute path then in the URL you need to supply the full directory path from the current working directory.
		  Remember to include PATH_BASE as well if it is set however there is no need to have a directory with the value of PATH_BASE, it is purely for
		  dealing with dumb LB.

		  Override the option '-public-root'

		- LOGIN_PATH - the url path to show the login page. Default is /login. Set it to empty to take the <PATH_BASSE>/login. When authentication failed
		  the app will re-direct to this path and show the simple login page.

		- PATH_BASE - Set all the path above relattive to this path base. Usefull for running behind a dumb load balancer which does not
		  support path rewrite; for eg. Tanzu AVI LB. If not required, set to empty string.

		  Better not to overlap the above three variables. Easiest way is to use relative to the current working dir for WEB_ROOT and
		  PUBLIC_ROOT (if needed). If the app is behind loadbalancer with extra path eg. '/my-ingress-path' then set PATH_BASE=/my-ingress-path
		  If the current working dir is the webroot itself set WEB_ROOT="" (empty string)

		- PORT - http port to listen. Default 8080.

		- AUTH_TYPE - default is jwt-cookie. Can be:
		  - 'jwt-cookie' - store and get the jwt token from session cookie
		  - 'jwt-query-param' - Get the jwt from query parameter. In this case need to provide a env var. Also there is no login helper for this case.
		    - QUERY_PARAM_KEY - The parameter key. Default is 'access_token'; that is the url is like https://<domain>/path?access_token=<jwt-token-string>
		  - 'auto' - This will try to get token from session cookie and if not then read from the query param. When it is validated a new session cookie
		    will be set.
		  - 'bypass' - This will disable authentication totally

		- SESSION_LIFE_TIME - the lifetime of the session cookie. Default is 1h (that is 1 hour)
		- SECURE_COOKIE - set the secure property of the session cookie. Default is true. Set to false if you are testing and not using https
		`)
	}
	flag.Parse()

	if method := os.Getenv("JWT_SIGN"); method != "" {
		signingMethod = method
	}
	if rsapubkey := os.Getenv("RSA_PUBLIC_KEY"); rsapubkey != "" {
		*rsaPubKeyPath = rsapubkey
	}
	switch signingMethod {
	case "HS256":
		jwtSecretStr := os.Getenv("JWT_SECRET")
		if jwtSecretStr == "" {
			log.Fatal("JWT_SECRET environment variable is required")
		}
		jwtSecret = []byte(jwtSecretStr)
	case "RS256":
		if *rsaPubKeyPath == "" {
			panic("[ERROR] Option jwt-sign is RS256 but option rsa-public-key is not provided\n")
		}
		rsaPubKeyBt, err := os.ReadFile(*rsaPubKeyPath)
		if err != nil {
			panic("[ERROR] can not read RSA Public Key content. Check your public key\n")
		}
		spkiBlock, _ := pem.Decode(rsaPubKeyBt)
		pubInterface, err := x509.ParseCertificate(spkiBlock.Bytes)
		if err != nil {
			panic("[ERROR] x509.ParseCertificate " + err.Error())
		}
		rsaPubKey = pubInterface.PublicKey.(*rsa.PublicKey)
	}

	loginPath = os.Getenv("LOGIN_PATH")
	if loginPath == "" {
		loginPath = "/login"
	}

	cookieName = os.Getenv("SESSION_COOKIE_NAME")
	if cookieName == "" {
		cookieName = "statis_web_srv_session"
	}

	secureCookieStr := os.Getenv("SECURE_COOKIE")
	var err error
	if secureCookieStr == "" {
		secureCookie = true
	} else {
		if secureCookie, err = strconv.ParseBool(secureCookieStr); err != nil {
			secureCookie = true
		}
	}

	listenPort := os.Getenv("PORT")
	if listenPort == "" {
		listenPort = *port
	}

	authType = os.Getenv("AUTH_TYPE") // jwt-cookie, jwt-query-param
	if authType == "" {
		authType = "jwt-cookie"
	}
	if authType == "bypass" {
		fmt.Fprintf(os.Stderr, "[WARN] AUTH_TYPE is bypass - we are not going to check auth\n")
	}

	queryParamKey = os.Getenv("QUERY_PARAM_KEY")
	if queryParamKey == "" {
		queryParamKey = "access_token"
	}

	// Path Base when dealing with LB without the re-write feature like Tanzu AVI (yuk)
	pathBase = os.Getenv("PATH_BASE")

	// Static file server
	webRoot = os.Getenv("WEB_ROOT")
	if webRoot == "" {
		webRoot = *staticDir
	}
	fmt.Fprintf(os.Stderr, "[INFO] Web root: %s\n", webRoot)

	publicRoot = os.Getenv("PUBLIC_ROOT")
	if publicRoot == "" {
		publicRoot = *publicDir
	}

	sessionLifeTimeStr := os.Getenv("SESSION_LIFE_TIME")
	if sessionLifeTimeStr == "" {
		sessionLifeTimeStr = "1h"
	}
	cookieLastDuration, _ = time.ParseDuration(sessionLifeTimeStr)

	if strings.HasPrefix(webRoot, ".") {
		stripPrefixPrivate = strings.TrimPrefix(webRoot, ".")
		privateRoutePath = stripPrefixPrivate + "/"
	} else {
		privateRoutePath = webRoot + "/"
		stripPrefixPrivate = webRoot
	}

	if strings.HasPrefix(publicRoot, ".") {
		stripPrefixPublic = strings.TrimPrefix(publicRoot, ".")
		publicRoutePath = stripPrefixPublic + "/"
	} else {
		publicRoutePath = publicRoot + "/"
		stripPrefixPublic = publicRoot
	}

	stripPrefixPrivate = pathBase + stripPrefixPrivate
	stripPrefixPublic = pathBase + stripPrefixPublic
	privateRoutePath = pathBase + privateRoutePath
	publicRoutePath = pathBase + publicRoutePath
	loginPath = pathBase + loginPath
	if cwd, err := os.Getwd(); err == nil {
		fmt.Fprintf(os.Stderr, "[INFO] Filesystem - Current working directory: '%s'", cwd)
	}
	fmt.Fprintf(os.Stderr, " PATH_BASE: '%s' WEB_ROOT: '%s' PUBLIC_ROOT: '%s' LOGIN_PATH: '%s'\n", pathBase, webRoot, publicRoot, loginPath)
	fmt.Fprintf(os.Stderr, "[INFO] URL Path - privateRoutePath: '%s' publicRoutePath: '%s' LOGIN_URL: '%s'\n", privateRoutePath, publicRoutePath, loginURL)

	mux := http.NewServeMux()

	// Routes
	mux.Handle(privateRoutePath, http.StripPrefix(stripPrefixPrivate, authenticate(http.FileServer(http.Dir(webRoot)))))
	mux.Handle(loginPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginPageHandler(w, r)
	}))
	if publicRoot != "" {
		mux.Handle(publicRoutePath, http.StripPrefix(stripPrefixPublic, http.FileServer(http.Dir(publicRoot))))
	}

	fmt.Printf("Server is running on port %s\n", listenPort)
	log.Fatal(http.ListenAndServe(":"+listenPort, mux))
}
