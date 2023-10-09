package main

import (
	"errors"
	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type DB struct {
	path string
	mu   *sync.RWMutex
}

type DBStructure struct {
	Chirps      map[int]Chirp         `json:"chirps"`
	Users       map[int]User          `json:"users"`
	Revocations map[string]Revocation `json:"revocations"`
}

type apiConfig struct {
	fileserverHits int
	DB             DB
	jwtSecret      string
	polkakey       string
}

type User struct {
	Email          string `json:"email"`
	Password       string `json:"-"`
	HashedPassword string `json:"hashed_password"`
	ID             int    `json:"id"`
	IsChirpyRed    bool   `json:"is_chirpy_red"`
}

type Revocation struct {
	Token     string    `json:"token"`
	RevokedAt time.Time `json:"revoked_at"`
}

var ErrAlreadyExists = errors.New("already exists")
var ErrNoAuthHeaderIncluded = errors.New("not auth header included in request")

// JWT

const (
	TokenTypeAccess  TokenType = "chirpy-access"
	TokenTypeRefresh TokenType = "chirpy-refresh"
)

type TokenType string

func main() {
	db, err := newDB("database.json")
	if err != nil {
		log.Fatal(err)
	}
	godotenv.Load(".env")

	polkaKey := os.Getenv("POLKA_KEY")
	if polkaKey == "" {
		log.Fatal("POLKA_KEY environment variable is not set")
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is not set")
	}

	apiCfg := apiConfig{
		fileserverHits: 0,
		DB:             *db,
		polkakey:       polkaKey,
	}

	r := chi.NewRouter()
	apiRouter := chi.NewRouter()
	adminRouter := chi.NewRouter()

	fsHandler := apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("."))))

	r.Handle("/app", fsHandler)
	r.Handle("/app/*", fsHandler)

	apiRouter.Get("/healthz", handlerReadiness)
	adminRouter.Get("/metrics", apiCfg.handleMetrics)
	apiRouter.Get("/reset", apiCfg.handleReset)

	apiRouter.Post("/chirps", apiCfg.handlerChirpsCreate)
	apiRouter.Get("/chirps", apiCfg.handlerChirpsRetrieve)
	apiRouter.Get("/chirps/{chirpID}", apiCfg.handlerChirpsGet)
	apiRouter.Delete("/chirps/{chirpID}", apiCfg.handlerChirpsDelete)

	r.Mount("/api", apiRouter)
	r.Mount("/admin", adminRouter)

	apiRouter.Post("/users", apiCfg.handlerUsersCreate)
	apiRouter.Put("/users", apiCfg.handlerUsersUpdate)

	apiRouter.Post("/login", apiCfg.handlerLogin)

	apiRouter.Post("/refresh", apiCfg.handlerRefresh)
	apiRouter.Post("/revoke", apiCfg.handlerRevoke)
	apiRouter.Post("/polka/webhooks", apiCfg.handlerWebhook)

	corsMux := middlewareCors(r)

	server := &http.Server{
		Addr:    ":8080",
		Handler: corsMux,
	}

	log.Fatal(server.ListenAndServe())

}
