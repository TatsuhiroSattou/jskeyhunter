package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sync"

	"jskeyhunter/discovery"
	"jskeyhunter/historical"
	"jskeyhunter/report"
	"jskeyhunter/scanner"
)

const historicalFallbackPath = "historical_seed.txt"

func main() {
	singleTarget := flag.String("u", "", "un solo target, ej: -u https://ejemplo.com")
	listFile := flag.String("l", "", "archivo con lista de targets (uno por línea), ej: -l targets.txt")
	outJSON := flag.String("o", "findings.json", "ruta del archivo JSON de salida")
	outHTML := flag.String("html", "report.html", "ruta del reporte HTML de salida")
	concurrency := flag.Int("c", 5, "cantidad de targets a escanear en paralelo")
	flag.Parse()

	var targets []string
	switch {
	case *singleTarget != "":
		targets = []string{*singleTarget}
	case *listFile != "":
		lines, err := readLines(*listFile)
		if err != nil {
			fmt.Println("error abriendo la lista de targets:", err)
			os.Exit(1)
		}
		targets = lines
	default:
		fmt.Println("uso:")
		fmt.Println("  un solo target:     jskeyhunter -u https://ejemplo.com")
		fmt.Println("  lista de targets:   jskeyhunter -l targets.txt")
		fmt.Println("\nflags opcionales: -o findings.json  -html report.html  -c 5")
		os.Exit(1)
	}

	sources := []historical.Source{
		historical.GauSource{},
		historical.WaybackSource{},
	}
	if _, err := os.Stat(historicalFallbackPath); err == nil {
		sources = append(sources, historical.LocalFileSource{Path: historicalFallbackPath})
	}

	rules := scanner.LoadRules()

	var (
		mu          sync.Mutex
		wg          sync.WaitGroup
		allFindings []scanner.Finding
	)

	sem := make(chan struct{}, *concurrency)

	for _, target := range targets {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fmt.Printf("\n[*] Escaneando target: %s\n", target)

			domain := extractDomain(target)
			histSeeds := historical.DiscoverAll(domain, sources)

			jsFiles, err := discovery.DiscoverJS(target, histSeeds)
			if err != nil {
				fmt.Println("  [!] error en discovery:", err)
				return
			}
			fmt.Printf("  [+] %d archivo(s) JS único(s) encontrado(s)\n", len(jsFiles))

			for _, js := range jsFiles {
				findings := scanner.ScanContent(js.URL, js.Content, rules)
				if len(findings) > 0 {
					fmt.Printf("  [!!!] %d hallazgo(s) en %s\n", len(findings), js.URL)
				}
				mu.Lock()
				allFindings = append(allFindings, findings...)
				mu.Unlock()
			}
		}(target)
	}

	wg.Wait()

	out, _ := json.MarshalIndent(allFindings, "", "  ")
	if err := os.WriteFile(*outJSON, out, 0644); err != nil {
		fmt.Println("[!] error guardando JSON:", err)
	}

	if err := report.WriteHTML(*outHTML, allFindings); err != nil {
		fmt.Println("[!] error generando reporte HTML:", err)
	}

	fmt.Printf("\n[*] Total hallazgos: %d\n", len(allFindings))
	fmt.Printf("[*] JSON: %s\n", *outJSON)
	fmt.Printf("[*] Reporte HTML: %s\n", *outHTML)
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := sc.Text(); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

func extractDomain(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	host := u.Host
	if host == "" {
		return target
	}
	return host
}
