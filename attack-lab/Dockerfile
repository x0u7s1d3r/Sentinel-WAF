# Attack Lab — image de l'application volontairement vulnérable (tests WAF).
# La base SQLite est en pur Go (modernc.org/sqlite) : pas de CGO, binaire statique.
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /out/attacklab .

FROM alpine:3.20
RUN adduser -D -H lab
COPY --from=build /out/attacklab /usr/local/bin/attacklab
# Fichiers légitimes de l'appli : base du path traversal / LFI.
RUN mkdir -p /app/pages && \
    printf 'Bienvenue sur la boutique.\nCeci est la page d accueil legitime.\n' > /app/pages/home.txt && \
    printf 'Nos conditions generales de vente...\n' > /app/pages/cgv.txt && \
    printf 'CONFIG_INTERNE\nadmin_token=lab-secret-do-not-share\n' > /app/pages/config.txt && \
    chown -R lab /app
USER lab
ENV LAB_LISTEN=:8080
EXPOSE 8080
ENTRYPOINT ["attacklab"]
