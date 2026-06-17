package flagging

import (
	"regexp"
	"strings"
)

type Sanitizer struct {
	Line     int
	Function string
	Variable string
}

type SanitizerDetector struct {
	patterns map[string]*regexp.Regexp
}

func NewSanitizerDetector() *SanitizerDetector {
	return &SanitizerDetector{
		patterns: map[string]*regexp.Regexp{
			"SQL_PREPARE":     regexp.MustCompile(`db\.Prepare\(|sql\.Prepare\(|Stmt\(`),
			"PATH_CLEAN":      regexp.MustCompile(`filepath\.Clean\(|filepath\.EvalSymlinks\(`),
			"REGEX_ESCAPE":    regexp.MustCompile(`regexp\.QuoteMeta\(`),
			"TEMPLATE_ESCAPE": regexp.MustCompile(`template\.HTMLEscape\(|template\.HTMLEscapeString\(`),
			"VALIDATION":      regexp.MustCompile(`regexp\.MatchString\(|strings\.Contains\(|validator\.|validation\(`),
			"INPUT_SANITIZER": regexp.MustCompile(`strings\.ReplaceAll\(|strings\.Replace\(|net\/url|url\.QueryEscape\(`),
		},
	}
}

func (d *SanitizerDetector) FindSanitizers(code string, varName string) []Sanitizer {
	lines := strings.Split(code, "\n")
	sanitizers := []Sanitizer{}

	for lineNum, line := range lines {
		if !strings.Contains(line, varName) {
			continue
		}

		for funcType, pattern := range d.patterns {
			if pattern.MatchString(line) {
				sanitizers = append(sanitizers, Sanitizer{
					Line:     lineNum + 1,
					Function: funcType,
					Variable: varName,
				})
			}
		}
	}

	return sanitizers
}
