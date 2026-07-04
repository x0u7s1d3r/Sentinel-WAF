// Package proxy est le cœur de la passerelle : il reçoit chaque requête, la
// fait normaliser (parser), l'inspecte via la chaîne de détection, puis décide
// de bloquer ou de transmettre au backend. C'est le point d'accroche unique où
// tous les moteurs de détection se branchent.
package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"sentinel-waf/internal/config"
	"sentinel-waf/internal/detector"
	"sentinel-waf/internal/parser"
	"sentinel-waf/internal/storage"
)

// Stats compteurs simples exposés par la passerelle (thread-safe).
type Stats struct {
	Total    atomic.Int64
	Blocked  atomic.Int64
	Detected atomic.Int64
	Allowed  atomic.Int64
}

// Gateway encapsule le reverse proxy et la logique WAF.
type Gateway struct {
	cfg    config.Config
	chain  *detector.Chain
	rp     *httputil.ReverseProxy // upstream par défaut (repli)
	router *Router                // routage multi-application par domaine
	log    *slog.Logger
	store  *storage.Store // peut être nil : le WAF fonctionne sans persistance
	Stats  Stats
}

// New construit la passerelle. store peut être nil (aucune persistance).
func New(cfg config.Config, chain *detector.Chain, log *slog.Logger, store *storage.Store, router *Router) (*Gateway, error) {
	target, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, err
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		http.Error(w, "Backend injoignable (démarrez l'application protégée).",
			http.StatusBadGateway)
	}
	if router == nil {
		router = NewRouter()
	}
	return &Gateway{cfg: cfg, chain: chain, rp: rp, router: router, log: log, store: store}, nil
}

// ServeHTTP implémente http.Handler : c'est le pipeline WAF complet.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	g.Stats.Total.Add(1)

	req, body := parser.Parse(r)
	// on remet le corps en place pour la transmission au backend
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	// Routage : quelle application est visée ? (par l'en-tête Host)
	// Si une application correspond, on applique SA politique (mode + seuil) et
	// on transmet à SON backend. Sinon, repli sur l'upstream par défaut.
	mode, threshold := g.cfg.Mode, g.cfg.Threshold
	upstream := g.rp
	appName := "default"
	if t, ok := g.router.Match(r.Host); ok {
		mode, threshold = t.App.Mode, t.App.Threshold
		upstream = t.rp
		appName = t.App.Name
	}

	result := g.chain.Inspect(req)
	verdict := g.decide(result.Score, mode, threshold)
	latency := time.Since(start).Microseconds()

	g.log.Info("request",
		"app", appName,
		"host", r.Host,
		"ip", clientIP(r),
		"method", req.Method,
		"path", req.Path,
		"verdict", verdict,
		"score", result.Score,
		"categories", strings.Join(result.Categories, ","),
		"engines", enginesOf(result.Findings),
		"latency_us", latency,
	)

	// Persistance asynchrone (ne bloque jamais le trafic ; ignorée si store nil).
	g.store.Log(storage.Event{
		ClientIP:   clientIP(r),
		Method:     req.Method,
		Path:       req.Path,
		Verdict:    verdict,
		Score:      result.Score,
		Categories: result.Categories,
		Findings:   result.Findings,
		LatencyUS:  latency,
	})

	switch verdict {
	case "blocked":
		g.Stats.Blocked.Add(1)
		g.writeBlock(w, result)
	case "detected":
		g.Stats.Detected.Add(1)
		upstream.ServeHTTP(w, r)
	default:
		g.Stats.Allowed.Add(1)
		upstream.ServeHTTP(w, r)
	}
}

func (g *Gateway) decide(score int, mode string, threshold int) string {
	if score < threshold {
		return "allowed"
	}
	if mode == "block" {
		return "blocked"
	}
	return "detected"
}

func (g *Gateway) writeBlock(w http.ResponseWriter, res detector.Result) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Sentinel-Verdict", "blocked")
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w, blockPage(res))
}

func enginesOf(fs []detector.Finding) string {
	seen := map[string]bool{}
	var out []string
	for _, f := range fs {
		if !seen[f.Engine] {
			seen[f.Engine] = true
			out = append(out, f.Engine)
		}
	}
	return strings.Join(out, ",")
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		return host[:i]
	}
	return host
}

func blockPage(res detector.Result) string {
	cats := strings.Join(res.Categories, ", ")
	if cats == "" {
		cats = "règle générique"
	}
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="fr"><head><meta charset="utf-8">`)
	b.WriteString(`<title>Requête bloquée — Sentinel WAF</title><style>`)
	b.WriteString(`body{font-family:system-ui,sans-serif;background:#0b0e14;color:#e4e9f2;`)
	b.WriteString(`display:flex;align-items:center;justify-content:center;height:100vh;margin:0}`)
	b.WriteString(`.c{max-width:520px;padding:2.5rem;border:1px solid #ff5d5d33;border-radius:14px;`)
	b.WriteString(`background:#131824;text-align:center}h1{color:#ff5d5d;font-size:1.5rem}`)
	b.WriteString(`code{background:#0b0e14;padding:.15rem .4rem;border-radius:5px;color:#ffcf6e}</style></head>`)
	b.WriteString(`<body><div class="c"><h1>⛔ Requête bloquée</h1>`)
	b.WriteString(`<p>Sentinel WAF a identifié cette requête comme malveillante.</p>`)
	b.WriteString(`<p>Catégories : ` + cats + `</p>`)
	b.WriteString(`<p>Score de menace : <code>`)
	b.WriteString(itoa(res.Score))
	b.WriteString(`</code></p></div></body></html>`)
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
