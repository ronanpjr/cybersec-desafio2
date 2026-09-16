// Package app implementa o servidor HTTP do laboratorio.
//
// Existem DUAS implementacoes do login, selecionadas por Server.Fixed:
//   - vulnerable (vuln.go): repassa o JSON recebido diretamente ao MongoDB,
//     permitindo injecao de operadores ($ne, $where, ...).
//   - corrigida   (fixed.go): allowlist de chaves + validacao de tipos +
//     construcao tipada da consulta.
//
// O restante do fluxo (esqueci a senha, token, minha conta) e compartilhado.
package app

import (
	"log"
	"net/http"

	"go.mongodb.org/mongo-driver/v2/mongo"

	"nosql-lab/internal/db"
)

// Marcadores de resposta identicos aos do lab oficial do PortSwigger.
const (
	MsgInvalid  = "Invalid username or password"
	MsgLocked   = "Account locked: please reset your password"
	MsgBadToken = "Invalid token"
)

// ResetField e o nome do campo que guarda o token de reset.
//
// No lab oficial esse nome e desconhecido para o atacante e precisa ser descoberto
// via injecao (Object.keys(this)[i]). Aqui ele e fixo para reprodutibilidade, mas o
// exploit continua obrigado a descobri-lo dinamicamente — nenhum endpoint o revela.
const ResetField = "passwordReset"

// Server agrega as dependencias dos handlers.
type Server struct {
	// Users e a colecao MongoDB consultada. Na versao corrigida aponta para uma
	// colecao com validador de schema estrito.
	Users *mongo.Collection
	// Fixed indica se o login corrigido deve ser usado.
	Fixed bool
}

// NewServer cria o servidor.
func NewServer(users *mongo.Collection, fixed bool) *Server {
	return &Server{Users: users, Fixed: fixed}
}

// Routes registra as rotas do laboratorio.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.Home)
	mux.HandleFunc("/login", s.Login)
	mux.HandleFunc("/forgot-password", s.ForgotPassword)
	mux.HandleFunc("/my-account", s.MyAccount)
	return mux
}

// Home redireciona para a pagina de login.
func (s *Server) Home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// Login despacha para a implementacao vulneravel ou corrigida.
func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		render(w, "login", map[string]any{})
		return
	}
	if s.Fixed {
		s.loginFixed(w, r)
		return
	}
	s.loginVuln(w, r)
}

// ForgotPassword trata GET (formulario/validacao de token) e POST (solicitar reset
// ou concluir a troca de senha). Esse fluxo NAO e o ponto de injecao; ele e comum
// as duas versoes.
func (s *Server) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.forgotPost(w, r)
		return
	}
	s.forgotGet(w, r)
}

// MyAccount mostra o usuario autenticado (prova de que o login funcionou).
func (s *Server) MyAccount(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err != nil || c.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	render(w, "my-account", map[string]any{"Username": c.Value})
}

// loginSuccess grava o cookie de sessao e redireciona para "minha conta".
func (s *Server) loginSuccess(w http.ResponseWriter, r *http.Request, username string) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: username, Path: "/"})
	http.Redirect(w, r, "/my-account", http.StatusFound)
}

// render executa um template de conteudo.
func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template %q: %v", name, err)
	}
}

// csrf devolve (criando se necessario) o token CSRF ligado ao cookie "csrf".
func (s *Server) csrf(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie("csrf"); err == nil && c.Value != "" {
		return c.Value
	}
	tok := db.RandomHex(16)
	http.SetCookie(w, &http.Cookie{Name: "csrf", Value: tok, Path: "/"})
	return tok
}

// checkCSRF valida o token do formulario contra o cookie (double-submit).
func checkCSRF(r *http.Request) bool {
	c, err := r.Cookie("csrf")
	if err != nil || c.Value == "" {
		return false
	}
	_ = r.ParseForm()
	return r.FormValue("csrf") == c.Value
}
