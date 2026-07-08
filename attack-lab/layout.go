package main

import (
	"fmt"
	"strings"
)

// layout rend la page complète : barre latérale de navigation + contenu.
func layout(title, active, body string) string {
	var nav strings.Builder
	nav.WriteString(`<a class="nav-home" href="/">◆ Attack Lab</a>`)
	nav.WriteString(`<div class="nav-group">Familles Sentinel</div>`)
	for _, v := range vulns {
		if v.Family == "bonus" {
			continue
		}
		cls := "nav-item"
		if active == "/"+v.Slug {
			cls += " active"
		}
		fmt.Fprintf(&nav, `<a class="%s" href="/%s">%s</a>`, cls, v.Slug, v.Title)
	}
	nav.WriteString(`<div class="nav-group">Classiques bonus</div>`)
	for _, v := range vulns {
		if v.Family != "bonus" {
			continue
		}
		cls := "nav-item"
		if active == "/"+v.Slug {
			cls += " active"
		}
		fmt.Fprintf(&nav, `<a class="%s" href="/%s">%s</a>`, cls, v.Slug, v.Title)
	}

	return `<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + title + ` — Attack Lab</title>
<style>` + css + `</style></head>
<body><div class="shell">
<aside class="sidebar">` + nav.String() + `</aside>
<main class="content">` + body + `</main>
</div></body></html>`
}

const css = `
:root{
  --bg:#0f1320; --panel:#161b2c; --panel2:#1c2338; --line:#28324c;
  --ink:#e7ecf6; --muted:#9aa6c2; --faint:#6b7799;
  --accent:#4f7cff; --danger:#ff5470; --safe:#37d39b; --warn:#ffb84d;
  --mono:'SFMono-Regular',ui-monospace,Menlo,Consolas,monospace;
  --sans:'Inter',system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:15px;line-height:1.55}
.shell{display:flex;min-height:100vh}
.sidebar{width:250px;flex-shrink:0;background:var(--panel);border-right:1px solid var(--line);padding:18px 12px;position:sticky;top:0;height:100vh;overflow:auto}
.nav-home{display:block;font-family:var(--mono);font-weight:700;font-size:17px;color:var(--accent);text-decoration:none;padding:8px 12px 16px}
.nav-group{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--faint);padding:14px 12px 6px}
.nav-item{display:block;padding:9px 12px;margin:2px 0;border-radius:8px;color:var(--muted);text-decoration:none;font-size:14px;transition:.15s}
.nav-item:hover{background:var(--panel2);color:var(--ink)}
.nav-item.active{background:var(--accent);color:#fff;font-weight:600}
.content{flex:1;padding:34px 40px;max-width:900px}
.hero h1{font-family:var(--mono);font-size:30px;margin:0 0 8px}
.hero p{color:var(--muted);max-width:640px}
.warn{margin:18px 0;padding:12px 16px;background:rgba(255,84,112,.08);border:1px solid rgba(255,84,112,.3);border-radius:10px;color:#ffb3c1;font-size:14px}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:14px;margin-top:22px}
.vcard{display:block;padding:16px;background:var(--panel);border:1px solid var(--line);border-radius:12px;text-decoration:none;color:inherit;transition:.15s}
.vcard:hover{border-color:var(--accent);transform:translateY(-2px)}
.vcard h3{margin:8px 0 6px;font-size:16px}
.vcard p{margin:0;color:var(--faint);font-size:12.5px;line-height:1.45}
.vtag{font-size:10px;text-transform:uppercase;letter-spacing:.06em;padding:2px 8px;border-radius:20px;font-weight:700}
.vtag.core{background:rgba(79,124,255,.16);color:#9db6ff}
.vtag.bonus{background:rgba(255,184,77,.16);color:#ffce8a}
.explain{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:20px}
.explain h2{margin:0 0 8px;font-size:20px}
.explain p{color:var(--muted);margin:0 0 12px}
.payloads{margin-top:10px;padding-top:12px;border-top:1px solid var(--line)}
.plabel{font-size:12px;color:var(--faint);text-transform:uppercase;letter-spacing:.05em}
.payloads ul{list-style:none;margin:8px 0 0;padding:0;display:flex;flex-wrap:wrap;gap:8px}
.payloads code{background:var(--panel2);border:1px solid var(--line);color:#ffd7de;padding:4px 10px;border-radius:6px;font-family:var(--mono);font-size:12.5px;cursor:copy}
.vform{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px 20px;display:flex;flex-direction:column;gap:8px}
.vform label{font-size:13px;color:var(--muted)}
.vform input{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:11px 13px;color:var(--ink);font-family:var(--mono);font-size:14px}
.vform input:focus{outline:none;border-color:var(--accent)}
.vform button,.btn{align-self:flex-start;background:var(--accent);color:#fff;border:none;border-radius:8px;padding:11px 20px;font-size:14px;font-weight:600;cursor:pointer;text-decoration:none;display:inline-block;margin-top:4px}
.vform button:hover,.btn:hover{filter:brightness(1.1)}
.linkrow{display:flex;gap:10px;flex-wrap:wrap;margin-top:8px}
.result{margin-top:18px;border-radius:12px;overflow:hidden;border:1px solid var(--line)}
.result pre{margin:0;padding:16px 18px;background:#0b0f1a;color:#d7e0f5;font-family:var(--mono);font-size:13px;white-space:pre-wrap;word-break:break-word}
.res-h{padding:10px 18px;font-weight:600;font-size:13px}
.res-vuln .res-h{background:rgba(255,84,112,.14);color:#ff9db0}
.res-neutral .res-h{background:rgba(55,211,155,.12);color:#7ee9c4}
.res-note{padding:12px 18px;margin:0;background:#0b0f1a;color:var(--warn);font-size:12.5px;border-top:1px solid var(--line)}
.xss-out{padding:16px 18px;background:#0b0f1a;color:#fff;font-size:15px}
.hint2{color:var(--faint);font-size:13px;margin-top:12px}
@media(max-width:720px){.shell{flex-direction:column}.sidebar{width:100%;height:auto;position:static}.content{padding:22px}}
`
