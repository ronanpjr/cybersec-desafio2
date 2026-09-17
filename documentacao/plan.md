# Plano — Lab: Exploiting NoSQL operator injection to extract unknown fields

> Disciplina de Cibersegurança. Ambiente 100% de testes (lab oficial PortSwigger + reimplementação local).
> Stack da reimplementação: **Go + MongoDB Go Driver**. Tudo dockerizado. Exploit em **Python (requests)**. Documentação em **Português**.

## 1. Contexto e objetivo

O lab pede: *logar como `carlos`*. Para isso é preciso exfiltrar o valor do *password reset token* do
usuário `carlos`, que está armazenado em um campo de **nome desconhecido** em um banco MongoDB.

Estratégia em três frentes:

1. **Lab ao vivo** — executar o mesmo exploit contra o lab hospedado do PortSwigger (enquanto a sessão expira).
2. **Reimplementação local** — app pequeno e fiel (endpoints, respostas, conta-alvo) para ser o artefato reproduzível.
3. **Correção** — versão blindada (allowlist de chaves + consulta tipada + schema estrito).

## 2. Mecanismo do lab (oráculo booleano)

`POST /login` recebe JSON e o repassa *cru* ao MongoDB (`findOne(req.body)`), permitindo injeção de operadores.

| Entrada (`POST /login`) | Resposta | Significado |
|---|---|---|
| `{"username":"carlos","password":"invalid"}` | `Invalid username or password` | sem match |
| `{"username":"carlos","password":{"$ne":"invalid"}}` | `Account locked` | `$ne` aceito; carlos tem token pendente |
| `..., "$where":"0"` | `Invalid username or password` | JS falsy → sem match |
| `..., "$where":"1"` | `Account locked` | JS truthy → match |
| `"$where":"Object.keys(this)[i].match('^.{pos}char.*')"` | `Account locked` ↔ `Invalid...` | oráculo p/ nome do campo |
| `"$where":"this.<campo>.match('^.{pos}char.*')"` | idem | oráculo p/ valor do token |

**Regra de negócio modelada:** `carlos` é semeado *já com* um token de reset (campo de nome desconhecido).
O login responde `Account locked` quando o usuário casa na query **e** possui token pendente. O estado
"locked" **é** a presença do token (espelha o lab).

## 3. Estrutura do repositório

```
cybersec-desafio2/
├── .gitignore                  # segredos, volumes, build
├── README.md                   # visão geral + como rodar
├── plan.md                     # este arquivo
├── docker-compose.yml          # mongo + seed + server
├── Dockerfile                  # build multi-stage Go (server + seed)
├── go.mod / go.sum
├── cmd/
│   ├── server/main.go          # app VULNERÁVEL
│   └── seed/main.go            # semeia wiener + carlos (token aleatório)
├── internal/
│   ├── app/vuln.go             # handlers vulneráveis (findOne(body) cru)
│   ├── app/fixed.go            # handlers CORRIGIDOS (allowlist + query tipada)
│   ├── app/routes.go           # roteamento compartilhado
│   └── db/db.go                # conexão + seed idempotente
├── exploit/
│   ├── exploit.py              # exfiltração booleana automatizada
│   └── requirements.txt
└── docs/
    ├── WRITEUP.md              # passos reprodutíveis + decisões + perguntas
    ├── LAB_LIVE.md             # execução contra o lab ao vivo
    └── PREVENTION.md           # correções
```

## 4. Componentes e decisões

**App Go (vulnerável)** — `net/http` + `html/template` + `go.mongodb.org/mongo-driver/v2`.
O login decodifica o JSON para `bson.M` e repassa integralmente a `FindOne`, reproduzindo a injeção de
operadores (`$ne`, `$where`). Endpoints:

- `GET /login` (form), `POST /login` (JSON → oráculo), `GET /my-account` (sucesso).
- `GET /forgot-password` (valida `?<campo>=valor` → `Invalid token` ou form de troca).
- `POST /forgot-password` (`username` → "e-mail de verificação", sem reset manual).
- `POST /reset-password` (troca senha + limpa token).

**Seed** — container init que insere `wiener` (login normal) e `carlos` (com `passwordResetToken` aleatório de
32 hex). Valor logado para verificação; o exploit o descobre de forma independente.

**Docker** — `docker-compose.yml` com `mongo:7` (healthcheck via `mongosh`), `seed` (init, sai 0) e `server`
(vulnerável, porta 8080). Um único `docker compose up --build` sobe tudo.

**Exploit Python** — `exploit.py` (`requests.Session`):
1. Confirma injeção (`$ne` → `Account locked`; `$where` 0/1).
2. Descobre nomes de campo via `Object.keys(this)[i].match('^.{pos}char.*')`.
3. Confirma o campo de token via `GET /forgot-password?campo=invalid` → `Invalid token`.
4. Exfiltra o valor do token por prefixos.
5. `GET /forgot-password?campo=token` → extrai inputs do form (CSRF incluso, se houver) → `POST /reset-password`
   → `POST /login` como carlos → flag de sucesso.

**Versão corrigida** — mesmos endpoints: allowlist de chaves (`username`, `password`), validação de tipos,
construção tipada `bson.M{"username": s, "password": s}` e schema estrito na coleção.

## 5. Perguntas em aberto (para discussão)

1. Nome do campo fixo (`passwordResetToken`) favorece reprodutibilidade; o lab real usa nome aleatório por
   instância. Randomizar via env para maior fidelidade mantendo o exploit 100% dinâmico?
2. Modelar "Account locked" como *presença do token* é suposição sobre a lógica interna do lab. Aceitável ou
   preferir um campo `locked` booleano separado?
3. `$where` está deprecado no MongoDB moderno (habilitado por padrão). Manter fiel ao lab ou documentar a
   mitigação extra `security.javascriptEnabled: false`?
4. Ordem de `Object.keys(this)` depende da ordem de inserção BSON (`_id` em [0]). Fixar ordem no seed?

## 6. Critérios de aceite

- `docker compose up --build` + `python exploit/exploit.py` resolve o lab sem info hardcoded de campo/token.
- Versão corrigida rejeita `$ne`/`$where` (400) e bloqueia a exfiltração.
- `.gitignore` cobre `.env`, dados do Mongo, builds, `node_modules`, `__pycache__`, logs, artefatos de seed.
- `docs/LAB_LIVE.md` registra a execução real (token efêmero redigido no commit).

---

## 7. Status final (executado)

**Concluído**

- **Lab ao vivo resolvido**: campo `passwordReset`, token exfiltrado, senha redefinida, login como
  `carlos`, banner **Solved**. Registro em `docs/LAB_LIVE.md`.
- **Reimplementação Go + MongoDB** (driver v2) dockerizada: `mongo` + `seed` + `server` (vuln, 8080)
  + `fixed` (8081). `docker compose --profile fixed up --build -d`.
- **Exploit Python** com busca binária por classe de regex + oráculo de comprimento + paralelismo
  por posição (`--workers 32`). Sem hardcode de nome de campo/token.
- **Validação local**: exploit resolve `:8080` e **falha** em `:8081` (injeção rejeitada por
  allowlist/tipos). Login legítimo (`wiener/peter`) segue 302 na versão corrigida.
- **Documentação**: `README.md`, `docs/WRITEUP.md`, `docs/LAB_LIVE.md`, `docs/PREVENTION.md`.
- **`.gitignore`** cobrindo segredos, volumes, builds e artefatos.

**Decisões efetivas (respondendo às perguntas da seção 5)**

1. Nome do campo **fixo** (`passwordReset`) para reprodutibilidade; descoberta sempre dinâmica.
2. "Account locked" modelado como **presença do token** (fiel ao comportamento observado).
3. `$where` **mantido** (fidelidade); mitigação `--noscripting` apenas documentada.
4. Ordem de campos **determinística** no seed (`bson.D`), mas o exploit **não** assume ordem.

**Bugs corrigidos durante a construção**

- Dockerfile: `ENTRYPOINT` → `CMD` (o `command:` do Compose era anexado, impedindo o seed de rodar).
- Parser de formulário: atributos sem aspas (`name=passwordReset`).
- Reset: preservar o campo do token (a substring "password" o sobrescrevia).

**Observação de uso**

- Após um solve, o token é limpo e a conta desbloqueia. Para reiniciar o lab:
  `docker compose run --rm seed`.
