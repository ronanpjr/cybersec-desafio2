package app

import (
	"encoding/json"
	"net/http"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// loginFixed e a implementacao CORRIGIDA.
//
// Aplicamos tres defesas em camadas:
//  1. ALLOWLIST de chaves: apenas "username" e "password" sao aceitas; qualquer
//     outra chave (ex.: "$where", "$ne") e rejeitada antes de tocar no banco.
//  2. VALIDACAO DE TIPOS: os valores precisam ser strings; objetos (operadores)
//     falham no Unmarshal e sao recusados.
//  3. CONSTRUCAO TIPADA DA CONSULTA: montamos bson.M apenas com strings controladas,
//     nunca com o corpo bruto do usuario.
//
// A colecao usada pela versao corrigida tambem possui um validador $jsonSchema
// estrito (ver cmd/seed), como defesa adicional no proprio MongoDB.
func (s *Server) loginFixed(w http.ResponseWriter, r *http.Request) {
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		render(w, "login", map[string]any{"Error": MsgInvalid})
		return
	}

	// (1) allowlist de chaves
	allowed := map[string]bool{"username": true, "password": true}
	for k := range raw {
		if !allowed[k] {
			render(w, "login", map[string]any{"Error": MsgInvalid})
			return
		}
	}

	// (2) validacao de tipos: somente strings
	var username, password string
	if err := json.Unmarshal(raw["username"], &username); err != nil {
		render(w, "login", map[string]any{"Error": MsgInvalid})
		return
	}
	if err := json.Unmarshal(raw["password"], &password); err != nil {
		render(w, "login", map[string]any{"Error": MsgInvalid})
		return
	}

	// (3) construcao tipada da consulta
	filter := bson.M{"username": username, "password": password}

	var user bson.M
	if err := s.Users.FindOne(r.Context(), filter).Decode(&user); err != nil {
		render(w, "login", map[string]any{"Error": MsgInvalid})
		return
	}
	if tok, _ := user[ResetField].(string); tok != "" {
		render(w, "login", map[string]any{"Error": MsgLocked})
		return
	}
	s.loginSuccess(w, r, username)
}
