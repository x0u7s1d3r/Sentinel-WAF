# Attack Lab — image de l'application volontairement vulnérable (tests WAF).
# Build multi-étapes : binaire Go statique puis image minimale.
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /out/attacklab .

FROM alpine:3.20
RUN adduser -D -H lab
COPY --from=build /out/attacklab /usr/local/bin/attacklab
USER lab
ENV LAB_LISTEN=:8080
EXPOSE 8080
ENTRYPOINT ["attacklab"]
