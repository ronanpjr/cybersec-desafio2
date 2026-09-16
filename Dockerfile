# syntax=docker/dockerfile:1

# --- Estagio de build: compila os 3 binarios (server, fixed, seed) ---
FROM golang:1.26 AS build
ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src

# Cache de dependencias
COPY go.mod go.sum ./
RUN go mod download

# Codigo-fonte
COPY . .

RUN go build -trimpath -o /out/server ./cmd/server \
 && go build -trimpath -o /out/fixed  ./cmd/fixed \
 && go build -trimpath -o /out/seed   ./cmd/seed

# --- Estagio de runtime ---
FROM alpine:3.20
RUN adduser -D -u 10001 app
WORKDIR /app
COPY --from=build /out/ /app/
USER app
EXPOSE 8080
# CMD (e nao ENTRYPOINT): o `command` do docker compose sobrescreve o CMD,
# permitindo rodar /app/server, /app/fixed ou /app/seed a partir da mesma imagem.
CMD ["/app/server"]
