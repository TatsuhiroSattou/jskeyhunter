// Package historical agrega URLs de JS que YA NO están linkeadas en el HTML
// actual pero existieron en algún momento (deploys viejos, JS huérfano que
// sigue respondiendo 200 aunque nadie lo referencia más). Esto es justo lo
// que un crawler en vivo (katana/playwright) se pierde, y por eso gau/wayback
// son un complemento, no un reemplazo.
package historical

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Source es cualquier cosa que, dado un dominio, devuelva URLs históricas de JS
type Source interface {
	Name() string
	Discover(domain string) ([]string, error)
}

// ---------- 1) gau real, si está instalado en el sistema ----------
// (lc/gau — pega contra wayback, otx, commoncrawl, urlscan)
type GauSource struct{}

func (g GauSource) Name() string { return "gau" }

func (g GauSource) Discover(domain string) ([]string, error) {
	path, err := exec.LookPath("gau")
	if err != nil {
		return nil, fmt.Errorf("binario 'gau' no encontrado en PATH (instalalo con: go install github.com/lc/gau/v2/cmd/gau@latest)")
	}

	// timeout defensivo: si algún provider de gau (wayback/otx/commoncrawl/
	// urlscan) se queda colgado resolviendo DNS o esperando respuesta, no
	// queremos que trabe el escaneo del target entero
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, path,
		"--subs",
		"--threads", "3",
		"--providers", "wayback,commoncrawl,otx,urlscan",
		domain,
	)
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("gau superó el timeout de 60s (probablemente algún provider no responde)")
	}
	if err != nil {
		return nil, err
	}
	return filterJS(strings.Split(string(out), "\n")), nil
}

// ---------- 2) Wayback Machine CDX API directo (sin binario externo) ----------
type WaybackSource struct{}

func (w WaybackSource) Name() string { return "wayback" }

func (w WaybackSource) Discover(domain string) ([]string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	target := fmt.Sprintf(
		"http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey&filter=mimetype:application/javascript",
		domain,
	)

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}
	// sin un User-Agent explícito, la API a veces responde con una página
	// de error/bloqueo en HTML en vez del JSON esperado
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; jskeyhunter/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, truncate(string(body), 150))
	}

	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" || trimmed == "[]" {
		return nil, nil // sin resultados, no es un error
	}
	if !strings.HasPrefix(trimmed, "[") {
		return nil, fmt.Errorf("respuesta inesperada (no es JSON): %s", truncate(trimmed, 150))
	}

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}

	var urls []string
	for i, row := range rows {
		if i == 0 || len(row) == 0 {
			continue // la primera fila es el header ["original"]
		}
		urls = append(urls, row[0])
	}
	return filterJS(urls), nil
}

// ---------- 3) Fallback local, para desarrollo/pruebas sin salida a internet ----------
// Lee un archivo de texto plano (una URL por línea) que vos armás vos mismo,
// simulando lo que gau/wayback te devolverían. Sirve para testear la lógica
// de "detectar JS que no está en el HTML vivo" sin depender de la red externa.
type LocalFileSource struct {
	Path string
}

func (l LocalFileSource) Name() string { return "local-fallback" }

func (l LocalFileSource) Discover(domain string) ([]string, error) {
	f, err := os.Open(l.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var urls []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && strings.Contains(line, domain) {
			urls = append(urls, line)
		}
	}
	return filterJS(urls), nil
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func filterJS(urls []string) []string {
	var out []string
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if strings.Contains(u, ".js") {
			out = append(out, u)
		}
	}
	return out
}

// DiscoverAll prueba las fuentes en orden de preferencia y junta todo lo que
// encuentre (no corta en la primera que funcione, porque cada una indexa
// cosas distintas).
func DiscoverAll(domain string, sources []Source) []string {
	seen := map[string]bool{}
	var all []string
	for _, s := range sources {
		urls, err := s.Discover(domain)
		if err != nil {
			fmt.Printf("  [historical:%s] no disponible: %v\n", s.Name(), err)
			continue
		}
		for _, u := range urls {
			if !seen[u] {
				seen[u] = true
				all = append(all, u)
			}
		}
		if len(urls) > 0 {
			fmt.Printf("  [historical:%s] %d URL(s) de JS histórico\n", s.Name(), len(urls))
		}
	}
	return all
}
