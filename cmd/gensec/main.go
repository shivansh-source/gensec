package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
	"github.com/shivansh-source/gensec/internal/config"
	"github.com/shivansh-source/gensec/internal/fixer"
	"github.com/shivansh-source/gensec/internal/flagging"
	"github.com/shivansh-source/gensec/internal/llm"
	"github.com/shivansh-source/gensec/internal/scanner"
)

func main() {
	godotenv.Load()

	if len(os.Args) < 2 {
		printUsage()
		return
	}

	command := os.Args[1]

	switch command {
	case "scan":
		cmdScan()
	case "fix":
		cmdFix()
	case "status":
		cmdStatus()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
	}
}

func cmdScan() {
	fmt.Println("\n🚀 GenSec Pro v3 - Data Flow Flagging Scanner")
	fmt.Println("=" + strings.Repeat("=", 59))
	fmt.Printf("Plan: %s\n", config.UserPlan)

	// Validate credentials
	if config.GroqAPIKey == "" {
		fmt.Println("❌ Missing GROQ_API_KEY")
		return
	}

	// Load file content
	fileContent := loadFileContent()
	if len(fileContent) == 0 {
		fmt.Println("⚠️  No .go files found")
		return
	}

	fmt.Printf("📁 Loaded %d files\n", len(fileContent))

	// Phase 1: Multi-Scanner
	multiScanner := scanner.NewMultiScanner(config.UserPlan)
	findings, err := multiScanner.ScanAll()
	if err != nil {
		fmt.Printf("❌ Scanning failed: %v\n", err)
		return
	}

	if len(findings) == 0 {
		fmt.Println("\n🎉 No vulnerabilities found!")
		return
	}

	// Phase 2: Data Flow Flagging
	flagEngine := flagging.NewFlagEngine()
	flags, err := flagEngine.ProcessFindings(findings, fileContent)
	if err != nil {
		fmt.Printf("❌ Flagging failed: %v\n", err)
		return
	}

	// Phase 3: LLM Triage
	triager := llm.NewLLMTriager()
	triaged, err := triager.TriageFlags(flags)
	if err != nil {
		fmt.Printf("⚠️  LLM triage failed: %v (using unfilitered flags)\n", err)
		triaged = flags
	}

	// Report
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("✅ SCAN COMPLETE")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("\nTotal findings (all scanners): %d\n", len(findings))
	fmt.Printf("After data-flow flagging: %d\n", len(flags))
	fmt.Printf("After LLM triage (confidence >= 60%%): %d\n", len(triaged))
	fmt.Printf("\nResults saved to:\n")
	fmt.Printf("  - report_flagged.json (all flags)\n")
	fmt.Printf("\n✅ Ready for PHASE 4: Batch Fix & Verify\n")
}

func cmdFix() {
	fmt.Println("\n🔧 GenSec Pro v3 - Batch Fixer")
	fmt.Println("=" + strings.Repeat("=", 59))

	// Load flagged findings from previous scan
	data, err := ioutil.ReadFile(config.ReportFileFlagged)
	if err != nil {
		fmt.Println("❌ No flagged findings found. Run 'scan' first.")
		return
	}

	var flags []flagging.Flag
	if err := json.Unmarshal(data, &flags); err != nil {
		fmt.Printf("❌ Failed to parse flags: %v\n", err)
		return
	}

	if len(flags) == 0 {
		fmt.Println("✅ No flags to fix!")
		return
	}

	// Load file content
	fileContent := loadFileContent()

	// Group by file
	flagsByFile := make(map[string][]flagging.Flag)
	for _, flag := range flags {
		flagsByFile[flag.File] = append(flagsByFile[flag.File], flag)
	}

	fmt.Printf("\n📋 Found %d files with flagged vulnerabilities\n", len(flagsByFile))

	// Batch fix
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("PHASE 4: BATCH FIX & VERIFICATION (LOOP)")
	fmt.Println(strings.Repeat("=", 60))

	fixer := fixer.NewBatchFixer()
	prCount := 0
	resultsCreated := []struct {
		file      string
		fixed     int
		failed    int
		escalated int
	}{}

	for file, fileFlags := range flagsByFile {
		if prCount >= config.MaxPRsPerRun {
			fmt.Printf("\n⚠️  Reached PR limit (%d)\n", config.MaxPRsPerRun)
			break
		}

		content, ok := fileContent[file]
		if !ok {
			fmt.Printf("⚠️  File not loaded: %s\n", file)
			continue
		}

		result := fixer.FixFileVulnerabilities(file, fileFlags, content)

		if result.Status != "failed" && result.FixedCode != "" {
			// Save fixed code
			if err := ioutil.WriteFile(file, []byte(result.FixedCode), 0644); err != nil {
				fmt.Printf("❌ Failed to save fixed file: %v\n", err)
				continue
			}

			fmt.Printf("\n✅ Fixed file saved: %s\n", file)
			prCount++

			resultsCreated = append(resultsCreated, struct {
				file      string
				fixed     int
				failed    int
				escalated int
			}{
				file:      file,
				fixed:     len(result.VulnsFixed),
				failed:    len(result.VulnsFailed),
				escalated: len(result.VulnsEscalated),
			})
		}

		// Print PR description (for reference)
		fmt.Printf("\n📝 PR Description:\n")
		fmt.Println(result.PRDescription)
	}

	// Summary
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("✅ BATCH FIX COMPLETE")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("\nFiles fixed: %d\n", prCount)
	for _, r := range resultsCreated {
		fmt.Printf("  - %s: %d fixed, %d failed, %d escalated\n", r.file, r.fixed, r.failed, r.escalated)
	}
	fmt.Printf("\n📝 Attempt tracking: %s\n", config.AttemptLogFile)
}

func cmdStatus() {
	fmt.Println("📊 GenSec Status")
	fmt.Printf("Plan: %s\n", config.UserPlan)
	fmt.Printf("GitHub User: %s\n", config.GitHubUser)

	if _, err := os.Stat(config.ReportFileFlagged); err == nil {
		data, _ := ioutil.ReadFile(config.ReportFileFlagged)
		var flags []flagging.Flag
		json.Unmarshal(data, &flags)
		fmt.Printf("Flagged findings: %d\n", len(flags))
	}
}

func loadFileContent() map[string]string {
	content := make(map[string]string)

	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			// Skip vendor, node_modules, .git, etc.
			if strings.HasPrefix(info.Name(), ".") || info.Name() == "vendor" || info.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}

		// Load .go files
		if strings.HasSuffix(path, ".go") {
			data, err := ioutil.ReadFile(path)
			if err == nil {
				content[path] = string(data)
			}
		}

		return nil
	})

	if err != nil {
		fmt.Printf("⚠️  Error loading files: %v\n", err)
	}

	return content
}

func printUsage() {
	fmt.Println(`
🤖 GenSec Pro v3 - Autonomous Vulnerability Fixer with Data Flow Flagging

Usage:
  go run cmd/gensec/main.go scan              # Scan, flag, and triage vulns
  go run cmd/gensec/main.go fix               # Batch fix vulnerabilities
  go run cmd/gensec/main.go status            # Show scan status

Environment Variables:
  GROQ_API_KEY                                # Groq API key (required)
  GITHUB_TOKEN                                # GitHub PAT
  GITHUB_USER                                 # GitHub username
  USER_PLAN                                   # "free", "pro", "enterprise"

Example:
  export GROQ_API_KEY=gsk_...
  export USER_PLAN=pro
  go run cmd/gensec/main.go scan
`)
}
