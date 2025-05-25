package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/patrickmn/go-cache"
)

// Token response from keycloak
// TODO: Test this against other OIDC services
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	IdToken          string `json:"id_token"`
	AccessExpiresIn  int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	Scope            string `json:"scope"`
}

type RefreshResponse struct {
	AccessToken     string `json:"access_token"`
	AccessExpiresIn int    `json:"expires_in"`
}

var verifierCache *cache.Cache
var accessTokenCache *cache.Cache
var refreshTokenCache *cache.Cache
var idTokenCache *cache.Cache

var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

type Config struct {
	BackendUrl   string
	AuthUrl      string
	ClientId     string
	ClientSecret string
}

var config *Config

// Samples a code verifier at random from the alphabet specified at
// https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
// The length should be between 43 and 128 to comply with the standard
func sampleCodeVerifier(length int) string {

	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	N := big.NewInt(int64(len(alphabet)))

	codeVerifier := make([]byte, length)

	for i := 0; i < length; i++ {
		idx, _ := rand.Int(rand.Reader, N)
		codeVerifier[i] = alphabet[idx.Int64()]
	}

	return string(codeVerifier)
}

// Computes the code challenge from a given code verifier
// The challenge is a hash that is computed according to
// https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
func computeCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// Send a refresh token request to the auth server
// It will return a new access token
func refreshTokenRequest(refreshToken string) (RefreshResponse, error) {
	logger.Debug(
		"Attempting to refresh access token",
		"refresh_token", refreshToken,
		"client_id", config.ClientId,
	)

	vals := make(url.Values)
	vals.Add("grant_type", "refresh_token")
	vals.Add("refresh_token", refreshToken)
	vals.Add("client_id", config.ClientId)
	vals.Add("client_secret", config.ClientSecret)

	var client http.Client
	tokenUrl, err := url.JoinPath(config.AuthUrl, "token")
	if err != nil {
		return RefreshResponse{}, err
	}
	auth_response, err := client.PostForm(tokenUrl, vals)

	if err != nil {
		return RefreshResponse{}, err
	}

	logger.Error("Acquired new access token")

	var tokens RefreshResponse
	json.NewDecoder(auth_response.Body).Decode(&tokens)

	return tokens, err
}

// The handler for the /auth/login endpoint at the BFF
// It will redirect the browser to the auth server
// with the necessary parameters to initiate the Authorization code flow with PKCE (front channel request)
func login(w http.ResponseWriter, r *http.Request) {
	authUrl, err := url.JoinPath(config.AuthUrl, "auth")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	auth_url, err := url.Parse(authUrl)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	callback_url, err := url.JoinPath("http://", r.Host, "/auth/callback")
	if err != nil {
		http.Error(w, "Invalid Host in header", http.StatusBadRequest)
		return
	}

	code_verifier := sampleCodeVerifier(64)
	code_verifier_uuid := uuid.NewString()
	code_challenge := computeCodeChallenge(code_verifier)

	verifierCache.Set(code_verifier_uuid, code_verifier, cache.DefaultExpiration)

	q := auth_url.Query()

	q.Set("scope", "openid api")
	q.Set("client_id", config.ClientId)
	q.Set("redirect_uri", callback_url)
	q.Set("response_type", "code")
	q.Set("code_challenge", code_challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", code_verifier_uuid)
	auth_url.RawQuery = q.Encode()

	http.Redirect(w, r, auth_url.String(), int(302))
}

// The callback is the endpoint that was specified as the redirect URI in
// the initial login redirect to the auth server. Therefore, after the user
// has authenticated with the auth server, they will be redirected to this
// endpoint (the second front channel request)
// A final back channel request between the BFF and the auth server completes the
// Authorization code flow with PKCE: The tokens end up at the BFF and can safely be
// stored server-side.
// Finally, the callback redirects the browser to the frontend and sets
// the session cookie (marked HTTP-only and secure)
func callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	code_verifier_uuid := r.URL.Query().Get("state")
	code_verifier, found := verifierCache.Get(code_verifier_uuid)

	if !found {
		logger.Error("Received callback with unknown state", "state", code_verifier_uuid)
		http.Error(w, "Internal Server Error", http.StatusBadRequest)
		return
	}

	defer verifierCache.Delete(code_verifier_uuid)

	var client http.Client

	callback_url, _ := url.JoinPath("http://", r.Host, "/auth/callback")

	vals := make(url.Values)
	vals.Add("grant_type", "authorization_code")
	vals.Add("code", code)
	vals.Add("redirect_uri", callback_url)
	vals.Add("client_id", config.ClientId)
	vals.Add("client_secret", config.ClientSecret)
	vals.Add("code_verifier", code_verifier.(string))

	tokenUrl, err := url.JoinPath(config.AuthUrl, "token")

	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	auth_response, err := client.PostForm(tokenUrl, vals)

	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var tokens TokenResponse
	json.NewDecoder(auth_response.Body).Decode(&tokens)

	sessionIdentifier := uuid.NewString()
	accessTokenCache.Set(sessionIdentifier, tokens.AccessToken, time.Duration(tokens.AccessExpiresIn*1000000000))
	refreshTokenCache.Set(sessionIdentifier, tokens.RefreshToken, time.Duration(tokens.RefreshExpiresIn*1000000000))
	idTokenCache.Set(sessionIdentifier, tokens.IdToken, cache.NoExpiration)

	http.SetCookie(w, &http.Cookie{
		Name:     "BFF_SESSION",
		Value:    sessionIdentifier,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteDefaultMode,
	})

	http.Redirect(w, r, "/", int(302))
}

// Claims that need to be read from ID token
type IdTokenClaims struct {
	PreferredUsername string `json:"preferred_username"`
	jwt.RegisteredClaims
}

// Since the ID token is also stored server side, an endpoint is used
// to obtain some basic user information. This is a design decision that is
// not too relevant for security. Alternatively, the ID token may be stored
// directly in the frontend. But this would require more JWT logic to
// be present there too.
func username(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("BFF_SESSION")
	if err == http.ErrNoCookie {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	idToken, found := idTokenCache.Get(sessionCookie.Value)
	if !found {
		http.Error(w, "Invalid session cookie", http.StatusBadRequest)
		return
	}

	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(idToken.(string), &IdTokenClaims{})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	} else if claims, ok := token.Claims.(*IdTokenClaims); ok {
		fmt.Fprintf(w, "%s", claims.PreferredUsername)
	} else {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

}

// The reverse proxy needs to add the authorization header for the current session
// additionally, it needs to acquire a new access token with the refresh token
func authDirector(r *http.Request) {
	sessionCookie, err := r.Cookie("BFF_SESSION")
	if err != nil {
		// No active session: Forward the requests to the API without any authorization header
		return
	}

	accessToken, found := accessTokenCache.Get(sessionCookie.Value)
	if !found {
		// session cookie set, but no active access token: attempt refresh

		refreshToken, found := refreshTokenCache.Get(sessionCookie.Value)
		if !found {
			logger.Info("unable to find refresh token for session", "session id", sessionCookie.Value)
			return
		}

		refreshResponse, err := refreshTokenRequest(refreshToken.(string))

		if err != nil {
			logger.Error("Error when attempting to refresh access token", "error", err)
			return
		}

		accessTokenCache.Set(sessionCookie.Value, refreshResponse.AccessToken, time.Duration(refreshResponse.AccessExpiresIn*1000000000))
		accessToken = refreshResponse.AccessToken
	}

	r.Header.Set("Authorization", "Bearer "+accessToken.(string))
}

// helper function for the file server that serves the frontend
func fileServerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if filepath.Ext(r.URL.Path) == ".js" {
			w.Header().Set("Content-Type", "text/javascript")
		}
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		next.ServeHTTP(w, r)
	})
}

func main() {

	err := godotenv.Load()
	if err != nil {
		logger.Error("Couldn't read .env ")
		return
	}

	config = &Config{
		BackendUrl:   os.Getenv("BACKEND_URL"),
		AuthUrl:      os.Getenv("AUTH_URL"),
		ClientId:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
	}

	verifierCache = cache.New(time.Minute, time.Minute)
	accessTokenCache = cache.New(cache.NoExpiration, time.Minute)
	refreshTokenCache = cache.New(cache.NoExpiration, time.Minute)
	idTokenCache = cache.New(cache.NoExpiration, time.Minute)

	http.HandleFunc("/auth/login", login)
	http.HandleFunc("/auth/callback", callback)
	http.HandleFunc("/auth/me", username)

	backend_url, err := url.Parse(config.BackendUrl)
	if err != nil {
		logger.Error("Can't parse backend url:", config.BackendUrl, err)
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(backend_url)
	defaultDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		defaultDirector(r)
		authDirector(r)
	}

	http.Handle("/api/", proxy)

	fs := http.FileServer(http.Dir("./public"))
	http.Handle("/", fileServerMiddleware(fs))
	http.ListenAndServe(":8000", nil)
}
