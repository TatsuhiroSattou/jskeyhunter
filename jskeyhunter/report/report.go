package report

import (
	"html/template"
	"os"
	"time"

	"jskeyhunter/scanner"
)

const tpl = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>jskeyhunter - Reporte</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; max-width: 980px; margin: 2rem auto; padding: 0 1rem; background: #0f1115; color: #e6e6e6; }
  h1 { font-size: 1.4rem; }
  .meta { color: #9aa0a6; margin-bottom: 1.5rem; }
  .summary { display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
  .card { background: #1a1d23; border: 1px solid #2a2e37; border-radius: 8px; padding: .75rem 1rem; }
  table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
  th, td { text-align: left; padding: .6rem .5rem; border-bottom: 1px solid #2a2e37; vertical-align: top; }
  th { color: #9aa0a6; font-weight: 600; font-size: .85rem; text-transform: uppercase; }
  tr:hover { background: #171a20; }
  .alta { color: #ff6b6b; font-weight: 600; }
  .media { color: #ffd166; font-weight: 600; }
  code { background: #1a1d23; padding: .15rem .4rem; border-radius: 4px; font-size: .85rem; }
  .url { word-break: break-all; font-size: .85rem; color: #8ab4f8; }
  .context { font-size: .8rem; color: #9aa0a6; word-break: break-all; }
  .empty { padding: 2rem; text-align: center; color: #9aa0a6; }
</style>
</head>
<body>
  <h1>🔑 jskeyhunter — Reporte de hallazgos</h1>
  <div class="meta">Generado: {{.GeneratedAt}}</div>

  <div class="summary">
    <div class="card"><strong>{{.Total}}</strong> hallazgos totales</div>
    <div class="card"><strong>{{.Alta}}</strong> confianza alta</div>
    <div class="card"><strong>{{.Media}}</strong> confianza media</div>
    <div class="card"><strong>{{.UniqueURLs}}</strong> JS afectados</div>
  </div>

  {{if .Findings}}
  <table>
    <tr><th>Confianza</th><th>Tipo</th><th>Match</th><th>JS</th><th>Contexto</th></tr>
    {{range .Findings}}
    <tr>
      <td class="{{.Confidence}}">{{.Confidence}}</td>
      <td>{{.Type}}</td>
      <td><code>{{.Match}}</code></td>
      <td class="url">{{.URL}}</td>
      <td class="context">{{.Context}}</td>
    </tr>
    {{end}}
  </table>
  {{else}}
  <div class="empty">No se encontraron secretos. 🎉</div>
  {{end}}
</body>
</html>
`

type reportData struct {
	GeneratedAt string
	Total       int
	Alta        int
	Media       int
	UniqueURLs  int
	Findings    []scanner.Finding
}

// WriteHTML genera un reporte HTML legible a partir de los hallazgos.
func WriteHTML(path string, findings []scanner.Finding) error {
	data := reportData{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Total:       len(findings),
		Findings:    findings,
	}

	urls := map[string]bool{}
	for _, f := range findings {
		urls[f.URL] = true
		if f.Confidence == "alta" {
			data.Alta++
		} else {
			data.Media++
		}
	}
	data.UniqueURLs = len(urls)

	t, err := template.New("report").Parse(tpl)
	if err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return t.Execute(f, data)
}
