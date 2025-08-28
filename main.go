package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
)

func main() {
	// create a new serveMux
	serverMux := http.NewServeMux()
	// create config struct
	endpointCfig := apiConfig{}

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
	serverMux.HandleFunc("POST /api/validate_chirp", validateChirp)

	// create a type server
	server := http.Server{
		Addr:    ":8080",
		Handler: serverMux,
	}

	// start up the server to listen for clients (this blocks until server is closed)
	err := server.ListenAndServe()
	if err != nil {
		fmt.Println("server error:", err)
	}

	fmt.Println("")
}

// struct for tracking api data
type apiConfig struct {
	fileserverHits atomic.Int32
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

// custom handler with state access type
func (cfg *apiConfig) reset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// set the new value
	cfg.fileserverHits.Swap(0)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func validateChirp(w http.ResponseWriter, r *http.Request) {
	// define struct to parse json
	type chirp_text struct {
		Body string `json:"body"`
	}

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
	text := getCleanChirp(chirp.Body)

	responseWithJson(w, 200, map[string]string{"cleaned_body": text})
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
