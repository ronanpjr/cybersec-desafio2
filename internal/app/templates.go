package app

import "html/template"

// templates reproduz as telas essenciais do lab oficial:
// login, "esqueci a senha", troca de senha e "minha conta".
// Os marcadores de mensagem ("Invalid username or password", "Account locked",
// "Invalid token") sao identicos aos do PortSwigger para que o mesmo exploit
// funcione contra o lab ao vivo e contra esta reimplementacao.
var templates = template.Must(template.New("").Parse(`
{{define "login"}}
<h1>Login</h1>
{{if .Error}}<p class=is-warning>{{.Error}}</p>{{end}}
<form class=login-form method=POST action="/login" onsubmit="return jsonSubmit(this,'/login')">
  <label>Username</label><input required type=username name=username autofocus>
  <label>Password</label><input required type=password name=password>
  <a href=/forgot-password>Forgot password?</a>
  <button class=button type=submit>Log in</button>
</form>
<script>
function jsonSubmit(form,url){
  event.preventDefault();
  fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:form.username.value,password:form.password.value})})
    .then(function(r){return r.text();})
    .then(function(t){document.open();document.write(t);document.close();});
  return false;
}
</script>
{{end}}

{{define "forgot"}}
<h1>Forgot password</h1>
{{if .Error}}<p class=is-warning>{{.Error}}</p>{{end}}
<form name=forgot-password class=login-form method=POST>
  <input required type="hidden" name="csrf" value="{{.CSRF}}">
  {{if .Token}}
    <input required type=hidden name=passwordReset value={{.Token}}>
    <label>New password</label><input required type=password name=new-password-1>
    <label>Confirm new password</label><input required type=password name=new-password-2>
  {{else}}
    <label>Please enter your username or email</label>
    <input required type=text name=username>
  {{end}}
  <button class=button type=submit>Submit</button>
</form>
{{end}}

{{define "my-account"}}
<h1>My account</h1>
<p>Logged in as {{.Username}}</p>
{{end}}

{{define "message"}}
<h1>Info</h1>
<p class=is-warning>{{.Message}}</p>
{{end}}
`))
