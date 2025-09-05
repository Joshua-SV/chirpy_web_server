package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

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
}

// declare struct to hold user info
type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

// define struct to parse json
type chirp_text struct {
	UserID    uuid.UUID `json:"user_id"`
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
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

	// parse the json request
	decode := json.NewDecoder(r.Body)
	chirp := chirp_text{}
	err := decode.Decode(&chirp)
	if err != nil {
		responseWithError(w, 500, "could not read request body")
		return
	}

	// check that the message chirp is not more than 140 chars long
	if len(chirp.Body) > 140 {
		responseWithError(w, 400, "chirp is too long")
		return
	}

	// clean request text from profane words
	chirp.Body = getCleanChirp(chirp.Body)

	// store chirp in database
	params := database.CreateChirpParams{
		Body:   chirp.Body,
		UserID: chirp.UserID,
	}

	chrpRes, err := cfg.db.CreateChirp(r.Context(), params)
	if err != nil {
		responseWithError(w, http.StatusFailedDependency, "could not store chirp in database")
		return
	}

	// prepare to return response to client
	chirp.ID = chrpRes.ID
	chirp.CreatedAt = chrpRes.CreatedAt
	chirp.UpdatedAt = chrpRes.UpdatedAt

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
		responseWithError(w, 500, "could not read request body")
		return
	}

	// create user in database
	userRes, err := cfg.db.CreateUser(r.Context(), user.Email)
	if err != nil {
		responseWithError(w, 500, "could not create user in database")
		return
	}

	// pass userRes fields to user struct type
	user.ID = userRes.ID
	user.Email = userRes.Email
	user.CreatedAt = userRes.CreatedAt
	user.UpdatedAt = userRes.UpdatedAt

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
