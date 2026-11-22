package scanner

import "regexp"

type Rule struct {
	Name    string
	Pattern *regexp.Regexp
}

// LoadRules devuelve el set de patrones conocidos. Pensado para después
// moverse a un YAML externo y poder agregar reglas sin recompilar.
func LoadRules() []Rule {
	return []Rule{
		{"AWS Access Key ID", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
		{"Stripe Secret Key", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`)},
		{"Stripe Publishable Key", regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`)},
		{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`)},
		{"GitHub Token", regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36,}`)},
		{"Firebase Server Key", regexp.MustCompile(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`)},
		{"JWT", regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)},
		{"Generic API Key Assignment", regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)["']?\s*[:=]\s*["']([A-Za-z0-9_\-.]{16,})["']`)},
		{"Bearer Token", regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9\-_.]{20,}`)},
		{"Mailgun API Key", regexp.MustCompile(`key-[0-9a-f]{32}`)},
		{"Twilio Account SID", regexp.MustCompile(`AC[0-9a-fA-F]{32}`)},
		{"Twilio Auth Token", regexp.MustCompile(`(?i)twilio[a-z0-9_\-]*["']?\s*[:=]\s*["']([0-9a-f]{32})["']`)},
		{"SendGrid API Key", regexp.MustCompile(`SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}`)},
		{"Heroku API Key", regexp.MustCompile(`(?i)heroku[a-z0-9_\-]*["']?\s*[:=]\s*["']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']`)},
		{"Shopify Access Token", regexp.MustCompile(`shpat_[0-9a-f]{32}`)},
		{"Shopify Shared Secret", regexp.MustCompile(`shpss_[0-9a-f]{32}`)},
		{"Telegram Bot Token", regexp.MustCompile(`\d{8,10}:AA[0-9A-Za-z_\-]{33}`)},
		{"Discord Webhook", regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+`)},
		{"NPM Token", regexp.MustCompile(`npm_[A-Za-z0-9]{36}`)},
		{"PostgreSQL Connection String", regexp.MustCompile(`postgres(?:ql)?://[^\s"'<>]+:[^\s"'<>]+@[^\s"'<>]+`)},
		{"MySQL Connection String", regexp.MustCompile(`mysql://[^\s"'<>]+:[^\s"'<>]+@[^\s"'<>]+`)},
		{"MongoDB Connection String", regexp.MustCompile(`mongodb(?:\+srv)?://[^\s"'<>]+:[^\s"'<>]+@[^\s"'<>]+`)},
		{"Redis Connection String", regexp.MustCompile(`redis://[^\s"'<>]*:[^\s"'<>]+@[^\s"'<>]+`)},
		{"Azure Storage Key", regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,}`)},
		{"PayPal/Braintree Access Token", regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`)},
		{"Square Access Token", regexp.MustCompile(`sq0atp-[0-9A-Za-z\-_]{22}`)},
	}
}
