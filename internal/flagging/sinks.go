package flagging

import (
	"regexp"
	"strings"
)

type SinkDetector struct {
	patterns map[string]*regexp.Regexp
}

func NewSinkDetector() *SinkDetector {
	return &SinkDetector{
		patterns: map[string]*regexp.Regexp{
			"SHELL_COMMAND":  regexp.MustCompile(`exec\.Command\(|cmd\.Run\(|bash|sh`),
			"SQL_QUERY":      regexp.MustCompile(`db\.Query\(|db\.Exec\(|sql\.Query\(|Query\(`),
			"XSS_OUTPUT":     regexp.MustCompile(`fmt\.Fprintf\(w,|w\.Write\(|w\.Header|ResponseWriter`),
			"WEAK_CRYPTO":    regexp.MustCompile(`md5\.|MD5\(|sha1\.|SHA1\(`),
			"FILE_OPERATION": regexp.MustCompile(`os\.Open\(|os\.Create\(|WriteFile\(|ioutil`),
			"PATH_OPERATION": regexp.MustCompile(`filepath\.|path\.`),
		},
	}
}

func (d *SinkDetector) DetectSink(code string, line int) (string, string) {
	lines := strings.Split(code, "\n")
	if line-1 >= len(lines) || line < 1 {
		return "", ""
	}

	codeLine := lines[line-1]

	for sinkType, pattern := range d.patterns {
		if pattern.MatchString(codeLine) {
			function := extractFunction(codeLine)
			return sinkType, function
		}
	}

	return "", ""
}

func extractFunction(code string) string {
	parts := strings.FieldsFunc(code, func(r rune) bool {
		return r == '(' || r == ' ' || r == '\t'
	})
	for i := len(parts) - 1; i > 0; i-- {
		if parts[i-1] == "." || (i > 0 && strings.Contains(parts[i], "Command")) {
			return strings.Join(parts[i-1:i+1], ".")
		}
	}
	return "unknown"
}
