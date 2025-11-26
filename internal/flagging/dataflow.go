package flagging

import (
	"fmt"
	"strings"
)

type DataFlowAnalyzer struct {
	sourceDetector    *SourceDetector
	sinkDetector      *SinkDetector
	sanitizerDetector *SanitizerDetector
}

func NewDataFlowAnalyzer() *DataFlowAnalyzer {
	return &DataFlowAnalyzer{
		sourceDetector:    NewSourceDetector(),
		sinkDetector:      NewSinkDetector(),
		sanitizerDetector: NewSanitizerDetector(),
	}
}

func (a *DataFlowAnalyzer) AnalyzeFinding(file string, line int, cwe, severity, message, snippet, fileContent string) *Flag {
	flag := &Flag{
		File:     file,
		Line:     line,
		CWE:      cwe,
		Severity: severity,
		Message:  message,
	}

	context := a.getCodeContext(fileContent, line, 5)
	flag.CodeContext = context

	// Step 1: Detect SOURCE
	sourceType, sourceName := a.sourceDetector.DetectSource(context, 6) // Line 6 in context (middle)
	if sourceType == "" {
		flag.Type = "RISKY_PATTERN"
		flag.Confidence = 0.5
		flag.Explanation = "Pattern detected, but source not clearly identified"
		return flag
	}

	flag.SourceType = sourceType
	flag.Source = sourceName

	// Step 2: Detect SINK
	sinkType, sinkFunc := a.sinkDetector.DetectSink(context, 6)
	if sinkType == "" {
		flag.Type = "SOURCE_DETECTED"
		flag.Confidence = 0.4
		flag.Explanation = fmt.Sprintf("Source detected (%s: %s), but sink not found in snippet", sourceType, sourceName)
		return flag
	}

	flag.SinkType = sinkType
	flag.Sink = sinkFunc

	// Step 3: Check for SANITIZERS
	sanitizers := a.sanitizerDetector.FindSanitizers(fileContent, sourceName)
	flag.IsSanitized = len(sanitizers) > 0

	if len(sanitizers) > 0 {
		sanitizerStrs := []string{}
		for _, s := range sanitizers {
			sanitizerStrs = append(sanitizerStrs, fmt.Sprintf("%s (line %d)", s.Function, s.Line))
		}
		flag.Sanitizer = strings.Join(sanitizerStrs, ", ")
	}

	// Step 4: Calculate confidence
	flag.Confidence = a.calculateConfidence(sourceType, sinkType, flag.IsSanitized, severity)

	// Step 5: Set type and explanation
	flag.Type = "SOURCE_TO_SINK"
	flag.Explanation = a.buildExplanation(sourceType, sourceName, sinkType, flag.IsSanitized)

	return flag
}

func (a *DataFlowAnalyzer) getCodeContext(code string, line int, contextLines int) string {
	lines := strings.Split(code, "\n")
	start := line - contextLines - 1
	if start < 0 {
		start = 0
	}
	end := line + contextLines
	if end > len(lines) {
		end = len(lines)
	}

	context := ""
	for i := start; i < end; i++ {
		prefix := "  "
		if i == line-1 {
			prefix = "→ "
		}
		if i >= 0 && i < len(lines) {
			context += fmt.Sprintf("%s%3d: %s\n", prefix, i+1, lines[i])
		}
	}

	return context
}

func (a *DataFlowAnalyzer) calculateConfidence(sourceType, sinkType string, isSanitized bool, severity string) float64 {
	baseConfidence := map[string]float64{
		"CRITICAL": 0.95,
		"HIGH":     0.85,
		"MEDIUM":   0.70,
		"LOW":      0.50,
	}[severity]

	if baseConfidence == 0 {
		baseConfidence = 0.50
	}

	if isSanitized {
		baseConfidence *= 0.3
	}

	if sourceType != "" && sinkType != "" {
		baseConfidence = baseConfidence*0.8 + 0.2
	}

	if baseConfidence > 1.0 {
		baseConfidence = 1.0
	}
	if baseConfidence < 0.0 {
		baseConfidence = 0.0
	}

	return baseConfidence
}

func (a *DataFlowAnalyzer) buildExplanation(sourceType, source, sinkType string, isSanitized bool) string {
	explanation := fmt.Sprintf("User input (%s: %s) flows to %s operation", sourceType, source, sinkType)

	if isSanitized {
		explanation += " with sanitization applied (lower risk)"
	} else {
		explanation += " WITHOUT sanitization (HIGH RISK)"
	}

	return explanation
}
