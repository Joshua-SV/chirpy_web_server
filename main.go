package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Joshua-SV/chirpy_web_server/internal/auth"

	"github.com/Joshua-SV/chirpy_web_server/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func main() {
	// load enviorment variables
	if err := godotenv.Load(); err != nil {
		// optional: ignore in prod; helpful log in dev
		fmt.Println("warning: .env not loaded:", err)
	}

	// open connection to database postgreSQL called chirpy
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Printf("could not open connection to database: %v", err)
		os.Exit(1)
	}

	if err := db.Ping(); err != nil {
		fmt.Printf("could not ping database: %v", err)
		os.Exit(1)
	}
	defer db.Close()

	// create a serveMux to handle which handler the endpoints will use
	serverMux := http.NewServeMux()

	// create config struct
	endpointCfig := apiConfig{}
	// give access to apiconfig to database
	endpointCfig.db = database.New(db)
	// set dev access good for local development
	endpointCfig.devAccess = os.Getenv("PLATFORM")

	// store secret key in memory
	endpointCfig.key = os.Getenv("SECRET_KEY")
	// store polka api key
	endpointCfig.polkaKey = os.Getenv("POLKA_KEY")

	// specify handler that will be a static file server
	serverMux.Handle("/app/", endpointCfig.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	// specify a custom handler
	serverMux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// endpoint handlers for admin namespace
	serverMux.HandleFunc("GET /admin/metrics", endpointCfig.metric)
	serverMux.HandleFunc("POST /admin/reset", endpointCfig.reset)

	// endpoint handlers for api namespace
	serverMux.HandleFunc("POST /api/chirps", endpointCfig.createChirp)
	serverMux.HandleFunc("GET /api/chirps", endpointCfig.getChirps)
	serverMux.HandleFunc("GET /api/chirps/{chirp_id}", endpointCfig.getChirpByID)
	serverMux.HandleFunc("POST /api/users", endpointCfig.createUser)
	serverMux.HandleFunc("POST /api/login", endpointCfig.login)
	serverMux.HandleFunc("POST /api/refresh", endpointCfig.refresh)
	serverMux.HandleFunc("POST /api/revoke", endpointCfig.revokeRefreshToken)
	serverMux.HandleFunc("PUT /api/users", endpointCfig.changeEmailAndPassword)
	serverMux.HandleFunc("DELETE /api/chirps/{chirpID}", endpointCfig.deleteChirpByID)
	serverMux.HandleFunc("POST /api/polka/webhooks", endpointCfig.setUserToChirpyRed)

	// create a type server
	server := http.Server{
		Addr:              ":8080",
		Handler:           serverMux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	// start up the server to listen for clients (this blocks until server is closed)
	err = server.ListenAndServe()
	if err != nil {
		fmt.Println("server error:", err)
	}
}

// struct for tracking api data
type apiConfig struct {
	db             *database.Queries
	fileserverHits atomic.Int32
	devAccess      string
	key            string
	polkaKey       string
}

// declare struct to hold user info
type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	IsRed     bool      `json:"is_chirpy_red"`
}

// define struct to parse json
type chirp_text struct {
	UserID    uuid.UUID `json:"user_id"`
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
}

// structs for webhook chirpy_red membership
type event_red struct {
	Event string     `json:"event"`
	Data  user_event `json:"data"`
}

type user_event struct {
	UserID uuid.UUID `json:"user_id"`
}

// middleware function for apiconfig
func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		w.Header().Set("Cache-Control", "no-store") // have the browser not use cache when this handler is used
		next.ServeHTTP(w, r)
	})
}

// custom handler with state access type
func (cfg *apiConfig) metric(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// get the value
	hits := cfg.fileserverHits.Load()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, hits)))
}

// custom handler with state access type will delete all users from database
func (cfg *apiConfig) reset(w http.ResponseWriter, r *http.Request) {
	// check if it has dev access
	if cfg.devAccess != "Dev" {
		w.WriteHeader(403)
		return
	}

	// delete all users in database chirpy
	err := cfg.db.DeleteAllUsers(r.Context())
	if err != nil {
		responseWithError(w, 500, "could not delete users in database")
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// set the new value
	cfg.fileserverHits.Swap(0)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) createChirp(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// get JWT header token string
	tokenStr, err := auth.GetBearerToken(r.Header)
	if err != nil {
		responseWithError(w, http.StatusUnauthorized, "no token found")
		return
	}

	userId, err := auth.ValidateJWT(tokenStr, cfg.key)
	if err != nil {
		responseWithError(w, http.StatusUnauthorized, "invalid token given")
		return
	}

	// parse the json request
	decode := json.NewDecoder(r.Body)
	chirp := chirp_text{}
	err = decode.Decode(&chirp)
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "could not read request body")
		return
	}

	// check that the message chirp is not more than 140 chars long
	if len(chirp.Body) > 140 {
		responseWithError(w, http.StatusForbidden, "chirp is too long")
		return
	}

	// clean request text from profane words
	chirp.Body = getCleanChirp(chirp.Body)

	// store chirp in database
	params := database.CreateChirpParams{
		Body:   chirp.Body,
		UserID: userId,
	}

	chrpRes, err := cfg.db.CreateChirp(r.Context(), params)
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "could not store chirp in database")
		return
	}

	// prepare to return response to client
	chirp.ID = chrpRes.ID
	chirp.CreatedAt = chrpRes.CreatedAt
	chirp.UpdatedAt = chrpRes.UpdatedAt
	chirp.UserID = userId

	responseWithJson(w, http.StatusCreated, chirp)
}

// helper function for JSON encoding
func responseWithJson(w http.ResponseWriter, statusCode int, payload interface{}) error {
	// parse data into json
	response, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	// specify header for server or browser
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// set a status code
	w.WriteHeader(statusCode)
	// return response json data
	w.Write(response)
	return nil
}

func responseWithError(w http.ResponseWriter, statusCode int, msg string) error {
	return responseWithJson(w, statusCode, map[string]string{"error": msg})
}

// helper function removes profane words with 4 **** then returns string
func getCleanChirp(text string) string {
	// get an array of string words
	lstWords := strings.Split(text, " ")

	// find profane word and replace
	for index, word := range lstWords {
		switch strings.ToLower(word) {
		case "kerfuffle":
			lstWords[index] = "****"
		case "sharbert":
			lstWords[index] = "****"
		case "fornax":
			lstWords[index] = "****"
		}
	}

	return strings.Join(lstWords, " ")
}

// create a user in the database given a json request from endpoint
func (cfg *apiConfig) createUser(w http.ResponseWriter, r *http.Request) {
	var user User

	defer r.Body.Close()

	// parse json request into user struct
	decode := json.NewDecoder(r.Body)
	err := decode.Decode(&user)
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "could not read request body")
		return
	}

	hashed, err := auth.HashPassword(user.Password)
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "could not create password")
		return
	}

	params := database.CreateUserParams{
		Email:          user.Email,
		HashedPassword: hashed,
	}

	// create user in database
	userRes, err := cfg.db.CreateUser(r.Context(), params)
	if err != nil {
		responseWithError(w, 500, "could not create user in database")
		return
	}

	// pass userRes fields to user struct type
	user.ID = userRes.ID
	user.Email = userRes.Email
	user.CreatedAt = userRes.CreatedAt
	user.UpdatedAt = userRes.UpdatedAt
	user.Password = ""
	user.IsRed = userRes.IsChirpyRed

	// respond back to client with user created information
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(201)

	// create json
	body, err := json.Marshal(user)
	if err != nil {
		responseWithError(w, 500, "could not create json body")
		return
	}
	w.Write(body)
}

// handler to get all chirps
func (cfg *apiConfig) getChirps(w http.ResponseWriter, r *http.Request) {

	// get chirps from database
	lst, err := cfg.db.GetAllChirps(r.Context())
	if err != nil {
		responseWithError(w, 500, "could not get chirps from database")
		return
	}

	// create an array to hold chirps
	chirps := make([]chirp_text, 0)

	// loop through chirps to append them to chirps array
	for _, item := range lst {
		chirp := chirp_text{
			UserID:    item.UserID,
			ID:        item.ID,
			CreatedAt: item.CreatedAt,
			UpdatedAt: item.UpdatedAt,
			Body:      item.Body,
		}

		chirps = append(chirps, chirp)
	}

	responseWithJson(w, http.StatusOK, chirps)
}

func (cfg *apiConfig) getChirpByID(w http.ResponseWriter, r *http.Request) {
	// get the string UUID passed by client
	strID := r.PathValue("chirp_id")

	if strID == "" {
		responseWithError(w, http.StatusBadRequest, "No ID passed")
		return
	}

	// convert string UUID to a literal UUID
	id, err := uuid.Parse(strID)
	if err != nil {
		responseWithError(w, http.StatusBadRequest, "invalid ID")
		return
	}

	// fetch the chirp from the database
	item, err := cfg.db.GetChirp(r.Context(), id)
	if err != nil {
		responseWithError(w, http.StatusNotFound, "could not find chirp from database")
		return
	}

	// prepare chirp to respond
	chirp := chirp_text{
		ID:        item.ID,
		UserID:    item.UserID,
		CreatedAt: item.CreatedAt,
		UpdatedAt: item.UpdatedAt,
		Body:      item.Body,
	}
	responseWithJson(w, http.StatusOK, chirp)
}

func (cfg *apiConfig) login(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var user User

	// parse the body into json
	decode := json.NewDecoder(r.Body)
	err := decode.Decode(&user)
	if err != nil {
		responseWithError(w, 500, "could not read request body")
		return
	}

	// get user info from database
	actualUser, err := cfg.db.GetUserByEmail(r.Context(), user.Email)
	if err != nil {
		responseWithError(w, http.StatusUnauthorized, "could not find user from database")
		return
	}

	// compare passwords
	err = auth.CheckPasswordvsHash(user.Password, actualUser.HashedPassword)
	if err != nil {
		responseWithError(w, http.StatusUnauthorized, "password incorrect")
		return
	}

	// set default login session token is JWT
	// if user.ExpireTimeSeconds <= 0 || user.ExpireTimeSeconds > 3600 {
	// 	user.ExpireTimeSeconds = 3600
	//}

	// create the JWT token string
	accessToken, err := auth.MakeJWT(actualUser.ID, cfg.key, time.Hour) // 1 hour expires
	if err != nil {
		responseWithError(w, http.StatusForbidden, "could not create token")
		return
	}

	// create refresh token
	refreshToken, _ := auth.MakeRefreshToken()
	refreshExpires := time.Now().UTC().Add(60 * 24 * time.Hour)
	params := database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    actualUser.ID,
		ExpiresAt: refreshExpires,
	}

	// store refresh token in database
	_, err = cfg.db.CreateRefreshToken(r.Context(), params)
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "could not store refresh token")
		return
	}

	responseWithJson(w, http.StatusOK, map[string]interface{}{
		"id":            actualUser.ID.String(),
		"email":         user.Email,
		"created_at":    actualUser.CreatedAt.String(),
		"updated_at":    actualUser.UpdatedAt.String(),
		"token":         accessToken,
		"refresh_token": refreshToken,
		"is_chirpy_red": actualUser.IsChirpyRed,
	})
}

func (cfg *apiConfig) refresh(w http.ResponseWriter, r *http.Request) {
	// parse refresh token string
	tokenStr, err := auth.GetBearerToken(r.Header)
	if err != nil {
		responseWithError(w, http.StatusUnauthorized, "missing refresh token")
		return
	}

	// get user info by checking if the refresh token is still valid
	user, err := cfg.db.GetUserFromRefreshToken(r.Context(), tokenStr)
	if err != nil {
		responseWithError(w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}

	// create new JWT token
	jwtToken, err := auth.MakeJWT(user.ID, cfg.key, time.Hour)
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "could not create access token")
		return
	}

	responseWithJson(w, http.StatusOK, map[string]string{
		"token": jwtToken,
	})
}

func (cfg *apiConfig) revokeRefreshToken(w http.ResponseWriter, r *http.Request) {
	// get refresh token string
	reToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		responseWithError(w, http.StatusUnauthorized, "missing refresh token")
		return
	}

	// update token to be revoked
	cfg.db.RevokeRefreshToken(r.Context(), reToken)

	// assume error means that token does not exist which is the same outcome as revoked
	w.WriteHeader(http.StatusNoContent)
}

// helper function to check access token and return user uuid
func (cfg *apiConfig) checkAccessToken(w http.ResponseWriter, r *http.Request) uuid.UUID {
	// get access token
	accessToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		responseWithError(w, http.StatusUnauthorized, "invalid token: missing token")
		return uuid.Nil
	}

	// check access token
	userID, err := auth.ValidateJWT(accessToken, cfg.key)
	if err != nil {
		responseWithError(w, http.StatusUnauthorized, "invalid token")
		return uuid.Nil
	}

	return userID
}

func (cfg *apiConfig) changeEmailAndPassword(w http.ResponseWriter, r *http.Request) {
	userID := cfg.checkAccessToken(w, r)
	if userID == uuid.Nil {
		return
	}

	defer r.Body.Close()

	// get json body from request
	var user User
	decode := json.NewDecoder(r.Body)
	err := decode.Decode(&user)
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "could not read request body")
		return
	}

	// create new hashed password
	hashedPass, err := auth.HashPassword(user.Password)
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "could not create hash")
		return
	}

	// store new email and password in database
	params := database.SetEmailAndPasswordParams{
		Email:          user.Email,
		HashedPassword: hashedPass,
		ID:             userID,
	}
	err = cfg.db.SetEmailAndPassword(r.Context(), params)
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "could not update email and password")
		return
	}

	responseWithJson(w, http.StatusOK, map[string]string{"email": user.Email})
}

func (cfg *apiConfig) deleteChirpByID(w http.ResponseWriter, r *http.Request) {
	userID := cfg.checkAccessToken(w, r)
	if userID == uuid.Nil {
		return
	}

	// get the string UUID passed by client
	strID := r.PathValue("chirpID")

	if strID == "" {
		responseWithError(w, http.StatusBadRequest, "No ID passed")
		return
	}

	chirpID, err := uuid.Parse(strID)
	if err != nil {
		responseWithError(w, http.StatusBadRequest, "invalid ID")
		return
	}

	// 1) Ensure chirp exists
	item, err := cfg.db.GetChirp(r.Context(), chirpID)
	if err != nil {
		// Not found
		if errors.Is(err, sql.ErrNoRows) {
			responseWithError(w, http.StatusNotFound, "chirp not found")
			return
		}
		responseWithError(w, http.StatusInternalServerError, "could not fetch chirp")
		return
	}

	// 2) Check ownership
	if item.UserID != userID {
		responseWithError(w, http.StatusForbidden, "not allowed to delete this chirp")
		return
	}

	// delete chirp based on id and user id ownership
	err = cfg.db.DeleteChirpByID(r.Context(), chirpID)
	if err != nil {
		// If someone deleted it between the check and now:
		if errors.Is(err, sql.ErrNoRows) {
			responseWithError(w, http.StatusNotFound, "chirp not found")
			return
		}
		responseWithError(w, http.StatusInternalServerError, "could not delete chirp")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// webhook function handler to give users chirpy red
func (cfg *apiConfig) setUserToChirpyRed(w http.ResponseWriter, r *http.Request) {
	// check webhook event had valid api key
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		responseWithError(w, http.StatusUnauthorized, fmt.Sprintf("invalid api key: %v", err))
		return
	}

	if apiKey != cfg.polkaKey {
		responseWithError(w, http.StatusUnauthorized, "invalid api key")
		return
	}

	defer r.Body.Close()
	// parse json request
	decode := json.NewDecoder(r.Body)
	var event event_red
	err = decode.Decode(&event)
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "could not read request body")
		return
	}

	// check event is chirpy red upgrade
	if event.Event != "user.upgraded" {
		responseWithError(w, http.StatusNoContent, "Not valid webhook event")
		return
	}

	// update user to chirpy red in database
	err = cfg.db.SetUserToRed(r.Context(), event.Data.UserID)
	if err != nil {
		responseWithError(w, http.StatusNotFound, "user not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
