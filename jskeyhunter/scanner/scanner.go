package scanner

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

type Finding struct {
	URL        string `json:"url"`
	Type       string `json:"type"`
	Match      string `json:"match"`
	Context    string `json:"context"`
	Confidence string `json:"confidence"`
}

var placeholderMarkers = []string{
	"example", "xxxx", "0000", "test", "dummy",
	"your_api_key", "changeme", "insert_key_here", "placeholder",
}

var quotedStringRe = regexp.MustCompile(`["']([A-Za-z0-9+/_\-=]{20,100})["']`)

// ScanContent corre todas las reglas conocidas + el fallback de entropía
// sobre un archivo JS ya descargado.
func ScanContent(url string, content string, rules []Rule) []Finding {
	var findings []Finding

	for _, rule := range rules {
		matches := rule.Pattern.FindAllStringIndex(content, -1)
		for _, loc := range matches {
			match := content[loc[0]:loc[1]]
			if isPlaceholder(match) {
				continue
			}
			findings = append(findings, Finding{
				URL:        url,
				Type:       rule.Name,
				Match:      mask(match),
				Context:    contextAround(content, loc[0], loc[1]),
				Confidence: "alta",
			})
		}
	}

	findings = append(findings, scanEntropy(url, content)...)
	return findings
}

// scanEntropy pesca strings "sueltas" entre comillas que no matchearon
// ningún patrón nombrado, pero tienen pinta de secreto por su aleatoriedad.
func scanEntropy(url string, content string) []Finding {
	var findings []Finding
	for _, m := range quotedStringRe.FindAllStringSubmatch(content, -1) {
		candidate := m[1]
		if isPlaceholder(candidate) {
			continue
		}
		if e := shannonEntropy(candidate); e >= 4.0 {
			findings = append(findings, Finding{
				URL:        url,
				Type:       "Posible secreto (alta entropía)",
				Match:      mask(candidate),
				Context:    "entropía: " + strconv.FormatFloat(e, 'f', 2, 64) + " bits/char",
				Confidence: "media",
			})
		}
	}
	return findings
}

func shannonEntropy(s string) float64 {
	freq := map[rune]float64{}
	for _, c := range s {
		freq[c]++
	}
	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func isPlaceholder(s string) bool {
	lower := strings.ToLower(s)
	for _, m := range placeholderMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// mask enmascara el secreto en el reporte para no filtrarlo vos mismo
// al guardar/compartir el output
func mask(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

func contextAround(content string, start, end int) string {
	from := start - 40
	if from < 0 {
		from = 0
	}
	to := end + 40
	if to > len(content) {
		to = len(content)
	}
	return strings.TrimSpace(strings.ReplaceAll(content[from:to], "\n", " "))
}
