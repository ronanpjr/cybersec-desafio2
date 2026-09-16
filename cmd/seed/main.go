// Command seed popula o MongoDB de forma idempotente.
//
// Cria/atualiza dois bancos:
//   - challenge        (versao vulneravel, sem validador de schema)
//   - challenge_fixed  (versao corrigida, com validador $jsonSchema estrito)
//
// Usuarios: "wiener" (login normal, sem token) e "carlos" (com token de reset
// pre-gravado, ou seja, conta "locked" desde o inicio — como no lab oficial).
package main

import (
	"context"
	"errors"
	"log"
	"os"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"nosql-lab/internal/db"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// userDoc monta o documento em ORDEM determinada (bson.D preserva a ordem).
// A ordem importa porque a exploracao enumera Object.keys(this)[i]; garantimos
// _id, username, password, email, passwordReset.
func userDoc(username, password, email, reset string) bson.D {
	d := bson.D{
		{Key: "username", Value: username},
		{Key: "password", Value: password},
		{Key: "email", Value: email},
	}
	if reset != "" {
		d = append(d, bson.E{Key: "passwordReset", Value: reset})
	}
	return d
}

// strictValidator e o schema estrito aplicado ao banco corrigido: apenas os
// campos previstos, com os tipos corretos, e nada de propriedades extras.
func strictValidator() bson.M {
	return bson.M{
		"$jsonSchema": bson.M{
			"bsonType": "object",
			"required": []string{"username", "password"},
			"properties": bson.M{
				"_id":           bson.M{"bsonType": "objectId"},
				"username":      bson.M{"bsonType": "string"},
				"password":      bson.M{"bsonType": "string"},
				"email":         bson.M{"bsonType": "string"},
				"passwordReset": bson.M{"bsonType": "string"},
			},
			"additionalProperties": false,
		},
	}
}

func seed(ctx context.Context, database *mongo.Database, strict bool) error {
	if strict {
		err := database.CreateCollection(ctx, "users",
			options.CreateCollection().SetValidator(strictValidator()))
		var cmdErr mongo.CommandError
		if err != nil && !(errors.As(err, &cmdErr) && cmdErr.Code == 48) { // 48 = NamespaceExists
			return err
		}
	}

	coll := database.Collection("users")
	if _, err := coll.DeleteMany(ctx, bson.M{}); err != nil {
		return err
	}
	_, err := coll.InsertMany(ctx, []any{
		userDoc("wiener", "peter", "wiener@example.com", ""),
		// senha do carlos e aleatoria/desconhecida; o token de reset existe desde o seed
		userDoc("carlos", db.RandomHex(16), "carlos@example.com", db.RandomHex(8)),
	})
	return err
}

func main() {
	ctx := context.Background()
	uri := env("MONGO_URI", "mongodb://localhost:27017")

	client, err := db.Connect(ctx, uri)
	if err != nil {
		log.Fatalf("erro ao conectar no MongoDB: %v", err)
	}

	if err := seed(ctx, client.Database(env("MONGO_DB", "challenge")), false); err != nil {
		log.Fatalf("seed (vulneravel): %v", err)
	}
	if err := seed(ctx, client.Database(env("MONGO_DB_FIXED", "challenge_fixed")), true); err != nil {
		log.Fatalf("seed (corrigido): %v", err)
	}
	log.Printf("seed concluido: wiener (login normal) e carlos (token de reset, conta locked)")
}
