package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/shivansh-source/gensec/internal/config"
	"github.com/shivansh-source/gensec/internal/flagging"
	"github.com/shivansh-source/gensec/internal/llm"
	"github.com/shivansh-source/gensec/internal/scanner"
)

//go:embed static/index.html
var webFS embed.FS

// GENSEC_WEB_FIXED_PATH locks the dashboard to scanning one fixed,
// server-chosen path regardless of what a client requests - this is what
// makes it safe to expose beyond localhost. Without it, /api/scan takes a
// filesystem path straight from client input, which is fine on your own
// machine but lets anyone hitting a public instance read arbitrary paths
// on whatever host it runs on.
const fixedPathEnvVar = "GENSEC_WEB_FIXED_PATH"

// scanCooldown serializes scans and caps how often the (real, metered) LLM
// API gets called - one scan at a time, at most once per cooldown window.
const scanCooldown = 5 * time.Second

var (
	scanMu       sync.Mutex
	lastScanTime time.Time
)

// scanResponse is what GET /api/scan returns to the dashboard.
type scanResponse struct {
	Path          string          `json:"path"`
	TotalFindings int             `json:"totalFindings"`
	TotalFlagged  int             `json:"totalFlagged"`
	Triaged       bool            `json:"triaged"`
	Findings      []flagging.Flag `json:"findings"`
	Warning       string          `json:"warning,omitempty"`
}

// cmdWeb starts a minimal read-only dashboard: point it at a path, it runs
// the same scan -> flag -> (optional) triage pipeline as `gensec scan` and
// renders the results in a browser. It never fixes anything or touches
// GitHub - view only, on purpose (see README).
//
// Not hardened for exposure beyond localhost/a trusted network: there's no
// auth, and the scanned path comes straight from client input.
func cmdWeb() {
	port := "8080"
	if len(os.Args) >= 3 && os.Args[2] != "" {
		port = os.Args[2]
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/api/scan", handleScanAPI)
	mux.HandleFunc("/api/config", handleConfigAPI)

	addr := ":" + port
	fmt.Printf("\n🌐 GenSec web dashboard: http://localhost:%s\n", port)
	fmt.Println("   (read-only: scans and shows findings, never fixes or opens a PR)")
	if fixed := os.Getenv(fixedPathEnvVar); fixed != "" {
		fmt.Printf("   demo mode: locked to scanning %q regardless of client input\n", fixed)
	}
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("web server error: %v", err)
	}
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := webFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "dashboard asset missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func handleConfigAPI(w http.ResponseWriter, r *http.Request) {
	fixed := os.Getenv(fixedPathEnvVar)
	writeJSON(w, map[string]interface{}{
		"demoMode":  fixed != "",
		"fixedPath": fixed,
	})
}

func handleScanAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	scanMu.Lock()
	defer scanMu.Unlock()
	if since := time.Since(lastScanTime); since < scanCooldown {
		wait := scanCooldown - since
		w.Header().Set("Retry-After", fmt.Sprintf("%.0f", wait.Seconds()))
		http.Error(w, fmt.Sprintf("please wait %.0fs between scans", wait.Seconds()), http.StatusTooManyRequests)
		return
	}
	// Recorded on the way out (see defer below), not here: a real scan
	// takes several seconds itself, so starting the cooldown clock now
	// would let it fully elapse *during* this very request, making the
	// limit a no-op against back-to-back requests.
	defer func() { lastScanTime = time.Now() }()

	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	scanRoot := req.Path
	if fixed := os.Getenv(fixedPathEnvVar); fixed != "" {
		// Demo mode: the client's requested path is ignored entirely.
		scanRoot = fixed
	} else if scanRoot == "" {
		scanRoot = "."
	}

	fileContent := loadFileContent(scanRoot)
	resp := scanResponse{Path: scanRoot}
	if len(fileContent) == 0 {
		resp.Warning = "no .go files found under this path"
		writeJSON(w, resp)
		return
	}

	multiScanner := scanner.NewMultiScanner(config.UserPlan(), scanRoot)
	findings, err := multiScanner.ScanAll()
	if err != nil {
		http.Error(w, fmt.Sprintf("scan failed: %v", err), http.StatusInternalServerError)
		return
	}
	resp.TotalFindings = len(findings)

	if len(findings) == 0 {
		writeJSON(w, resp)
		return
	}

	flagEngine := flagging.NewFlagEngine()
	flags, err := flagEngine.ProcessFindings(findings, fileContent)
	if err != nil {
		http.Error(w, fmt.Sprintf("flagging failed: %v", err), http.StatusInternalServerError)
		return
	}
	resp.TotalFlagged = len(flags)
	resp.Findings = flags

	if config.GroqAPIKey() != "" {
		triager := llm.NewLLMTriager()
		if triaged, err := triager.TriageFlags(flags); err == nil {
			resp.Findings = triaged
			resp.Triaged = true
		} else {
			resp.Warning = fmt.Sprintf("LLM triage failed, showing untriaged flags: %v", err)
		}
	} else {
		resp.Warning = "GROQ_API_KEY not set - showing untriaged flags (no confidence scoring)"
	}

	writeJSON(w, resp)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}
