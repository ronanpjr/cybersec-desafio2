// Package db concentra a conexao com o MongoDB e utilidades compartilhadas.
package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Connect abre a conexao com o MongoDB e valida a conectividade com Ping.
// Em caso de falha retorna erro; o chamador decide se aborta.
func Connect(ctx context.Context, uri string) (*mongo.Client, error) {
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx, nil); err != nil {
		return nil, err
	}
	return client, nil
}

// RandomHex gera n bytes aleatorios criptograficamente seguros e os codifica em hex.
// Usado para o token de reset (8 bytes => 16 caracteres hex, igual ao lab oficial).
func RandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
