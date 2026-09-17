# Prevenção — como corrigir a injeção de operador NoSQL

A causa raiz é **passar entrada do usuário diretamente como o documento de consulta**. O MongoDB
interpreta chaves iniciadas por `$` como operadores (`$ne`, `$where`, `$regex`, ...), então o
atacante deixa de controlar apenas *valores* e passa a controlar a **estrutura da consulta**.

## Vulnerável (`internal/app/vuln.go`)

```go
var filter bson.M
json.NewDecoder(r.Body).Decode(&filter)      // corpo inteiro, chaves incluídas
s.Users.FindOne(r.Context(), filter).Decode(&user)
```

## Corrigido (`internal/app/fixed.go`) — três camadas

### (1) Allowlist de chaves aceitas
```go
allowed := map[string]bool{"username": true, "password": true}
for k := range raw {
    if !allowed[k] {
        render(w, "login", map[string]any{"Error": MsgInvalid})
        return
    }
}
```
`$where`, `$ne` e qualquer outra chave são rejeitadas antes de chegar ao banco.

### (2) Validação de tipos (somente strings)
```go
var username, password string
if err := json.Unmarshal(raw["username"], &username); err != nil { /* 400 */ }
if err := json.Unmarshal(raw["password"], &password); err != nil { /* 400 */ }
```
`{"password":{"$ne":"invalid"}}` **falha** aqui, pois um objeto não decodifica como string.

### (3) Construção tipada da consulta
```go
filter := bson.M{"username": username, "password": password}
```
A consulta é montada apenas com strings controladas — nunca com o corpo bruto do usuário.

### (4) Schema estrito no MongoDB (defesa em profundidade)

O `cmd/seed` cria a coleção do banco corrigido com um validador `$jsonSchema`:

```go
validator := bson.M{"$jsonSchema": bson.M{
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
}}
database.CreateCollection(ctx, "users", options.CreateCollection().SetValidator(validator))
```

### (5) Desabilitar JavaScript no servidor (defesa extra, opcional)

Como o vetor mais forte aqui é o `$where` (execução de JavaScript), o MongoDB pode ser iniciado com
o script server-side desabilitado:

```
mongod --noscripting          # ou: security.javascriptEnabled: false no mongod.conf
```

> **Atenção:** isso é uma mitigação de infraestrutura, **não** substitui a validação de entrada.
> Se o `$where` for bloqueado mas as chaves ainda forem passadas cruas, outros operadores
> (`$ne`, `$regex`, `$gt`, ...) continuam exploráveis. A correção principal são as camadas (1)–(3).

## Verificação

Com os containers no ar:

```bash
# VULNERÁVEL: injecao aceita
curl -s -H 'Content-Type: application/json' \
  -d '{"username":"carlos","password":{"$ne":"invalid"}}' http://localhost:8080/login
# -> Account locked: please reset your password

# CORRIGIDO: injecao bloqueada
curl -s -H 'Content-Type: application/json' \
  -d '{"username":"carlos","password":{"$ne":"invalid"}}' http://localhost:8081/login
# -> Invalid username or password

# CORRIGIDO: chave $where bloqueada
curl -s -H 'Content-Type: application/json' \
  -d '{"username":"carlos","password":{"$ne":"invalid"},"$where":"1"}' http://localhost:8081/login
# -> Invalid username or password

# CORRIGIDO: login legitimo continua funcionando (HTTP 302)
curl -s -o /dev/null -w '%{http_code}\n' -H 'Content-Type: application/json' \
  -d '{"username":"wiener","password":"peter"}' http://localhost:8081/login
# -> 302
```

O exploit completo contra o alvo corrigido falha já na etapa de confirmação:

```bash
python3 exploit/exploit.py --target http://localhost:8081
# AssertionError: $ne nao aceito (sem 'Account locked')
```

## Checklist de prevenção (PortSwigger)

- [x] Sanitizar/validar entrada com **allowlist** de caracteres e **de chaves**.
- [x] Usar **consultas parametrizadas/tipadas**, não concatenar entrada na consulta.
- [x] Aplicar **schema** na coleção.
- [x] Desabilitar JavaScript server-side quando não for necessário.
