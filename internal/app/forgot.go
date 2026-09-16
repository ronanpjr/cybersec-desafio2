package app

import (
	"net/http"

	"go.mongodb.org/mongo-driver/v2/bson"

	"nosql-lab/internal/db"
)

// forgotGet trata o GET de /forgot-password.
//
//   - Sem o parametro do token: mostra o formulario "informe o usuario/e-mail".
//   - Com o parametro do token: se o token existir, mostra o formulario de troca
//     de senha; caso contrario, exibe "Invalid token".
//
// IMPORTANTE: este endpoint CONFIRMA um nome de campo (retornando "Invalid token")
// mas nunca o revela. O atacante ainda precisa descobrir o nome via injecao.
func (s *Server) forgotGet(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get(ResetField)
	if token == "" {
		render(w, "forgot", map[string]any{"CSRF": s.csrf(w, r)})
		return
	}

	var user bson.M
	if err := s.Users.FindOne(r.Context(), bson.M{ResetField: token}).Decode(&user); err != nil {
		render(w, "forgot", map[string]any{"CSRF": s.csrf(w, r), "Error": MsgBadToken})
		return
	}
	render(w, "forgot", map[string]any{"CSRF": s.csrf(w, r), "Token": token})
}

// forgotPost trata o POST de /forgot-password, com dois fluxos:
//
//   - Com "username": solicita o reset (o token e gerado/gravado na conta, mas o
//     e-mail de verificacao impede que o atacante conclua o reset sozinho). Esse
//     passo e o que faz o campo do token passar a existir no documento.
//   - Com o token + novas senhas: conclui a troca de senha e limpa o token.
func (s *Server) forgotPost(w http.ResponseWriter, r *http.Request) {
	if !checkCSRF(r) {
		render(w, "message", map[string]any{"Message": "Invalid CSRF token"})
		return
	}

	if username := r.FormValue("username"); username != "" {
		tok := db.RandomHex(8) // 16 caracteres hex, igual ao token do lab
		_, _ = s.Users.UpdateOne(r.Context(),
			bson.M{"username": username},
			bson.M{"$set": bson.M{ResetField: tok}})
		render(w, "message", map[string]any{
			"Message": "If the account exists, an email has been sent.",
		})
		return
	}

	token := r.FormValue(ResetField)
	p1 := r.FormValue("new-password-1")
	p2 := r.FormValue("new-password-2")
	if token == "" || p1 == "" || p1 != p2 {
		render(w, "forgot", map[string]any{"CSRF": s.csrf(w, r), "Error": MsgBadToken})
		return
	}

	res, err := s.Users.UpdateOne(r.Context(),
		bson.M{ResetField: token},
		bson.M{
			"$set":   bson.M{"password": p1},
			"$unset": bson.M{ResetField: ""},
		})
	if err != nil || res.MatchedCount == 0 {
		render(w, "forgot", map[string]any{"CSRF": s.csrf(w, r), "Error": MsgBadToken})
		return
	}
	render(w, "message", map[string]any{"Message": "Password changed. Please log in."})
}
