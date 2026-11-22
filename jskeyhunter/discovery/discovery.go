package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"
)

// JSFile representa un archivo JS descubierto y descargado
type JSFile struct {
	URL     string
	Content string
	Hash    string
}

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
var importRe = regexp.MustCompile(`(?i)(?:import\s+.*?from\s+|import\(|["'\x60])([^"'\x60]+?\.js[^"'\x60]*)["'\x60)]`)

var client = &http.Client{Timeout: 10 * time.Second}

const maxConcurrentDownloads = 8

// DiscoverJS descubre todos los JS de un target: HTML en vivo + imports
// anidados + source maps + lo que le pases como "historicalSeeds" (gau,
// wayback, etc.). Todo el fetch/scan se hace en paralelo con un tope de
// goroutines (maxConcurrentDownloads) para no tumbar el target a pedidos.
func DiscoverJS(target string, historicalSeeds []string) ([]JSFile, error) {
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		seen    = map[string]bool{}
		results []JSFile
	)

	base, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	html, err := fetch(target)
	if err != nil {
		return nil, fmt.Errorf("no se pudo cargar %s: %w", target, err)
	}

	seeds := extractURLs(html, base, scriptSrcRe)
	seeds = append(seeds, historicalSeeds...)

	sem := make(chan struct{}, maxConcurrentDownloads)

	var process func(u string)
	process = func(u string) {
		defer wg.Done()

		mu.Lock()
		if seen[u] {
			mu.Unlock()
			return
		}
		seen[u] = true
		mu.Unlock()

		sem <- struct{}{}
		content, err := fetch(u)
		<-sem
		if err != nil {
			return
		}

		h := sha256.Sum256([]byte(content))
		hash := hex.EncodeToString(h[:])

		mu.Lock()
		results = append(results, JSFile{URL: u, Content: content, Hash: hash})
		mu.Unlock()

		// seguir imports anidados dentro de este JS (chunks, módulos, etc.)
		jsBase, _ := url.Parse(u)
		for _, n := range extractURLs(content, jsBase, importRe) {
			mu.Lock()
			already := seen[n]
			mu.Unlock()
			if !already {
				wg.Add(1)
				go process(n)
			}
		}

		// intentar el source map correspondiente
		mapURL := u + ".map"
		mu.Lock()
		mapAlready := seen[mapURL]
		if !mapAlready {
			seen[mapURL] = true
		}
		mu.Unlock()
		if !mapAlready {
			sem <- struct{}{}
			mapContent, err := fetch(mapURL)
			<-sem
			if err == nil {
				hm := sha256.Sum256([]byte(mapContent))
				mu.Lock()
				results = append(results, JSFile{URL: mapURL, Content: mapContent, Hash: hex.EncodeToString(hm[:])})
				mu.Unlock()
			}
		}
	}

	for _, s := range seeds {
		wg.Add(1)
		go process(s)
	}
	wg.Wait()

	return dedupeByHash(results), nil
}

func fetch(u string) (string, error) {
	resp, err := client.Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func extractURLs(content string, base *url.URL, re *regexp.Regexp) []string {
	var out []string
	matches := re.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		raw := m[len(m)-1]
		resolved, err := base.Parse(raw)
		if err != nil {
			continue
		}
		out = append(out, resolved.String())
	}
	return out
}

func dedupeByHash(files []JSFile) []JSFile {
	seenHash := map[string]bool{}
	var out []JSFile
	for _, f := range files {
		if seenHash[f.Hash] {
			continue
		}
		seenHash[f.Hash] = true
		out = append(out, f)
	}
	return out
}
