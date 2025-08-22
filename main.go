package main

import (
	"fmt"
	"net/http"
)

func main() {
	// create a new serveMux
	serverMux := http.NewServeMux()

	// specify handle
	serverMux.Handle("/app/", http.StripPrefix("/app", http.FileServer(http.Dir("."))))
	// specify a custom handler
	serverMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// create a type server
	server := http.Server{
		Addr:    ":8080",
		Handler: serverMux,
	}

	// start up the server to listen for clients
	err := server.ListenAndServe()
	if err != nil {
		fmt.Println("server error:", err)
	}

	fmt.Println("")
}
