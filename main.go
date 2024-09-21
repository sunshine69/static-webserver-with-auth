package main

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// JWT Claims structure
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

var cookieName, authType, queryParamKey string
var secureCookie bool
var cookieLastDuration time.Duration

// Path to the web root dir. This will be relative path to the current root; like ./static. The route path will be absolute like /static
// and then be stripped off. This can be an absolute path though started with / but the route will be the same exactly absolute path
// No slash / at the end
var (
	webRoot    string
	publicRoot string
)

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

func ParseJWTToken(token string, claims *Claims) (parsedToken *jwt.Token, err error) {
	switch signingMethod {
	case "HS256":
		parsedToken, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	case "RS256":
		parsedToken, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return rsaPubKeyContent, nil
		})
	}
	return
}

// Handler for the login page
func loginPageHandler(c *gin.Context) {
	switch c.Request.Method {
	case http.MethodGet:
		loginTemplate.Execute(c.Writer, gin.H{})
	case http.MethodPost:
		token, _ := c.GetPostForm("token")
		claims := &Claims{}
		// Parse and validate the JWT token
		parsedToken, err := ParseJWTToken(token, claims)
		if err != nil || !parsedToken.Valid {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		// Token is valid, set a session cookie
		c.SetCookie(cookieName, token, int(cookieLastDuration.Seconds()), "/", "", secureCookie, true)

		// Redirect to the home page or protected resource
		c.Redirect(http.StatusFound, strings.TrimPrefix(webRoot, "."))
		return
	}
}

// Middleware to check JWT in cookies
func AuthenticateMidleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var token string
		var err error
		redirect := func(c *gin.Context) {
			// Redirect to login if all hopes lost
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
		}
		switch authType {
		case "jwt-cookie":
			token, err = c.Cookie(cookieName)
			if err != nil {
				redirect(c)
			}
		case "jwt-query-param":
			token, _ = c.GetQuery(queryParamKey)
			if token == "" {
				redirect(c)
			}
		case "auto":
			token, err = c.Cookie(cookieName)
			if err != nil {
				token, _ = c.GetQuery(queryParamKey)
			}
			if token == "" {
				redirect(c)
			}
		case "bypass":
			c.Next()
		}

		claims := &Claims{}
		parsedToken, err := ParseJWTToken(token, claims)
		if err != nil || !parsedToken.Valid {
			// Redirect to login if token is invalid
			redirect(c)
		}
		// if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
		// 	// Doing something more with claims
		// 	fmt.Println(claims["foo"], claims["nbf"])
		// } else {
		// 	fmt.Println(err)
		// }
		// Token is valid, set a session cookie
		c.SetCookie(cookieName, token, int(cookieLastDuration.Seconds()), "/", "", secureCookie, true)
		// Token is valid, continue to the requested resource
		c.Next()
	}
}

var (
	jwtSecret                       []byte
	signingMethod, rsaPubKeyContent string
)

func main() {
	// Command-line arguments
	staticDir := flag.String("web-root", "./static", "Directory to serve static files from")
	publicDir := flag.String("public-root", "./pub", "Public Directory to serve static files from")
	port := flag.String("port", "8080", "Port to listen on")
	flag.StringVar(&signingMethod, "jwt-sign", "HS256", "JWT Signing method. Value can be HS256 (HMAC using SHA256) or RS256 (RSA using SHA256)")
	rsaPubKey := flag.String("rsa-public-key", "", "RSA public key used when signing method is RS256")

	flag.Usage = func() {
		flag.PrintDefaults()
		fmt.Println(`           
							***** static web server with jwt auth *****
		This web server serves static files and protected with jwt auth. Apart from command flags the env vars below will override it
		- JWT_SECRET - The secret to validate the jwt token
		- SESSION_COOKIE_NAME - the session cookie name used to get the jwt token. Default is statis_web_srv_session

		- WEB_ROOT - The protected directory path to serve files from. Can be relative path to the current dir, or absolute path.
		- PUBLIC_ROOT - The non protected directory path to serve files from. Can be relative path to the current dir, or absolute path.
		  public dir should be relative to the WEB_ROOT to avoid route conflict if possible.

		  The html path will be the same without dot if it is relative. Override cmd flag 'web-root'

		- PORT - http port to listen. Default 8080.
		- AUTH_TYPE - default is jwt-cookie. Can be:
		  - 'jwt-cookie' - store and get the jwt token from session cookie
		  - 'jwt-query-param' - Get the jwt from query parameter. In this case need to provide a env var. Also there is no login helper for this case.
		    - QUERY_PARAM_KEY - The parameter key. Default is 'access_token'; that is the url is like https://<domain>/path?access_token=<jwt-token-string>
		  - 'auto' - This will try to get token from session cookie and if not then read from the query param. When it is validated a new session cookie 
		    will be set.
			
		- SESSION_LIFE_TIME - the lifetime of the session cookie. Default is 1h (that is 1 hour)
		- SECURE_COOKIE - set the secure property of the session cookie. Default is true. Set to false if you are testing and not using https
		`)
	}
	flag.Parse()

	switch signingMethod {
	case "HS256":
		jwtSecretStr := os.Getenv("JWT_SECRET")
		if jwtSecretStr == "" {
			log.Fatal("JWT_SECRET environment variable is required")
		}
		jwtSecret = []byte(jwtSecretStr)
	case "RS256":
		if *rsaPubKey == "" {
			panic("[ERROR] Option jwt-sign is RS256 but option rsa-public-key is not provided\n")
		}
		rsaPubKeyBt, err := os.ReadFile(*rsaPubKey)
		if err != nil {
			panic("[ERROR] can not read RSA Public Key content. Check your public key\n")
		}
		rsaPubKeyContent = string(rsaPubKeyBt)
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

	queryParamKey = os.Getenv("QUERY_PARAM_KEY")
	if queryParamKey == "" {
		queryParamKey = "access_token"
	}

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
	fmt.Fprintf(os.Stderr, "[INFO] Public root: %s\n", publicRoot)

	sessionLifeTimeStr := os.Getenv("SESSION_LIFE_TIME")
	if sessionLifeTimeStr == "" {
		sessionLifeTimeStr = "1h"
	}
	cookieLastDuration, _ = time.ParseDuration(sessionLifeTimeStr)

	router := gin.Default()
	router.Any("/login", loginPageHandler)
	rPublic := router.Group(publicRoot)
	rPublic.StaticFS("/", http.Dir(publicRoot))
	rPrivate := router.Group(webRoot, AuthenticateMidleware())
	rPrivate.StaticFS("/", http.Dir(webRoot))

	fmt.Fprintf(os.Stderr, "Signing method %s\n", signingMethod)
	fmt.Fprintf(os.Stderr, "Server is running on port %s\n", listenPort)
	router.Run(":" + listenPort)
}
