package flagging

import (
	"regexp"
	"strings"
)

type SourceDetector struct {
	patterns map[string]*regexp.Regexp
}

func NewSourceDetector() *SourceDetector {
	return &SourceDetector{
		patterns: map[string]*regexp.Regexp{
			"URL_PARAM":  regexp.MustCompile(`r\.URL\.Query\(\)\.Get\(|r\.Query`),
			"FORM_VALUE": regexp.MustCompile(`r\.FormValue\(|r\.PostFormValue\(`),
			"POST_FORM":  regexp.MustCompile(`r\.PostForm`),
			"HEADER":     regexp.MustCompile(`r\.Header\.Get\(|request\.Header`),
			"ENV_VAR":    regexp.MustCompile(`os\.Getenv\(`),
			"NETWORK":    regexp.MustCompile(`ioutil\.ReadAll\(|io\.ReadAll\(|Decoder`),
			"FILE":       regexp.MustCompile(`os\.ReadFile\(|ioutil\.ReadFile\(`),
		},
	}
}

func (d *SourceDetector) DetectSource(code string, line int) (string, string) {
	lines := strings.Split(code, "\n")
	if line-1 >= len(lines) || line < 1 {
		return "", ""
	}

	codeLine := lines[line-1]

	for sourceType, pattern := range d.patterns {
		if pattern.MatchString(codeLine) {
			varName := extractVariableName(codeLine)
			return sourceType, varName
		}
	}

	return "", ""
}

func extractVariableName(code string) string {
	parts := strings.Split(code, ":=")
	if len(parts) >= 2 {
		return strings.TrimSpace(parts[0])
	}
	parts = strings.Split(code, "=")
	if len(parts) >= 2 {
		return strings.TrimSpace(parts[0])
	}
	return "unknown"
}
