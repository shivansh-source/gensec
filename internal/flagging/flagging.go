package flagging

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/shivansh-source/gensec/internal/config"
	"github.com/shivansh-source/gensec/internal/scanner"
)

type FlagEngine struct {
	analyzer *DataFlowAnalyzer
}

func NewFlagEngine() *FlagEngine {
	return &FlagEngine{
		analyzer: NewDataFlowAnalyzer(),
	}
}

func (fe *FlagEngine) ProcessFindings(findings []scanner.Finding, fileContent map[string]string) ([]Flag, error) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("🚩 PHASE 2: DATA FLOW FLAGGING")
	fmt.Println(strings.Repeat("=", 60))

	flags := []Flag{}

	for idx, finding := range findings {
		fmt.Printf("\n  [%d/%d] Analyzing: %s (%s)\n", idx+1, len(findings), finding.VulnID, finding.CWE)

		content, ok := fileContent[finding.File]
		if !ok {
			fmt.Printf("    ⚠️  File not loaded: %s\n", finding.File)
			continue
		}

		flag := fe.analyzer.AnalyzeFinding(
			finding.File,
			finding.Line,
			finding.CWE,
			finding.Severity,
			finding.Message,
			finding.Snippet,
			content,
		)

		flag.VulnID = finding.VulnID
		flag.Tools = []string{finding.Tool}

		fmt.Printf("    Type: %s\n", flag.Type)
		fmt.Printf("    Source: %s (%s)\n", flag.Source, flag.SourceType)
		fmt.Printf("    Sink: %s (%s)\n", flag.Sink, flag.SinkType)
		fmt.Printf("    Sanitized: %v\n", flag.IsSanitized)
		fmt.Printf("    Confidence: %.2f%%\n", flag.Confidence*100)

		flags = append(flags, *flag)
	}

	sort.Slice(flags, func(i, j int) bool {
		return flags[i].Confidence > flags[j].Confidence
	})

	fmt.Printf("\n✅ Total flags created: %d\n", len(flags))

	if err := fe.saveFlagsToFile(flags); err != nil {
		return nil, err
	}

	return flags, nil
}

func (fe *FlagEngine) saveFlagsToFile(flags []Flag) error {
	data, err := json.MarshalIndent(flags, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(config.ReportFileFlagged, data, 0644)
}
