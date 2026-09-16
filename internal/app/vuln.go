package app

import (
	"encoding/json"
	"net/http"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// loginVuln e a implementacao VULNERAVEL.
//
// O corpo JSON inteiro e decodificado em bson.M e repassado DIRETAMENTE ao
// FindOne. Isso permite injecao de operadores NoSQL:
//
//	{"username":"carlos","password":{"$ne":"invalid"}}          -> $ne aceito
//	{"username":"carlos","password":{"$ne":"x"},"$where":"..."}  -> $where avaliado
//
// A resposta distingue "conta existe mas esta com reset pendente" (Account locked)
// de "sem match" (Invalid username or password), formando o oraculo booleano.
func (s *Server) loginVuln(w http.ResponseWriter, r *http.Request) {
	var filter bson.M
	if err := json.NewDecoder(r.Body).Decode(&filter); err != nil {
		render(w, "login", map[string]any{"Error": MsgInvalid})
		return
	}

	var user bson.M
	if err := s.Users.FindOne(r.Context(), filter).Decode(&user); err != nil {
		render(w, "login", map[string]any{"Error": MsgInvalid})
		return
	}

	// A presenca do token de reset e o que define a conta "locked" (identico ao lab).
	if tok, _ := user[ResetField].(string); tok != "" {
		render(w, "login", map[string]any{"Error": MsgLocked})
		return
	}

	username, _ := user["username"].(string)
	s.loginSuccess(w, r, username)
}
