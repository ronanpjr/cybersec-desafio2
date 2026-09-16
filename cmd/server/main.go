// Command server sobe a versao VULNERAVEL do laboratorio (injecao de operador NoSQL).
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"nosql-lab/internal/app"
	"nosql-lab/internal/db"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	ctx := context.Background()
	uri := env("MONGO_URI", "mongodb://localhost:27017")
	dbName := env("MONGO_DB", "challenge")
	addr := env("ADDR", ":8080")

	client, err := db.Connect(ctx, uri)
	if err != nil {
		log.Fatalf("erro ao conectar no MongoDB: %v", err)
	}
	users := client.Database(dbName).Collection("users")

	srv := app.NewServer(users, false)
	log.Printf("versao VULNERAVEL em %s (db=%s)", addr, dbName)
	log.Fatal(http.ListenAndServe(addr, srv.Routes()))
}
