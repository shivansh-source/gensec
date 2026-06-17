# GenSec Architecture

## System Overview

GenSec is a **5-phase autonomous vulnerability detection and remediation system** built in Go with LLM integration.

```
┌─────────────────────────────────────────────────────────────────┐
│                    GenSec Pro v3 - Architecture                 │
└─────────────────────────────────────────────────────────────────┘

                          Input: Go Codebase
                                  │
                                  ▼
                    ┌──────────────────────────┐
                    │  PHASE 1: Multi-Scanner  │
                    │  Detection               │
                    └──────────┬───────────────┘
                               │
    ┌──────────────┬───────────┼───────────┬──────────────┐
    │              │           │           │              │
    ▼              ▼           ▼           ▼              ▼
  SAST         Pattern      Static      Dependency   Configuration
  Scanner      Matcher      Analyzer    Checker      Analyzer
    │              │           │           │              │
    └──────────────┴───────────┴───────────┴──────────────┘
                               │
                         12 Raw Findings
                               │
                               ▼
                    ┌──────────────────────────┐
                    │  PHASE 2: Data Flow      │
                    │  Flagging Engine         │
                    └──────────┬───────────────┘
                               │
          ┌─────��──────────────┴────────────────────┐
          │                                         │
    Context Analysis                       Data Flow Tracing
          │                                         │
    ┌─────▼──────────────────────────────────────┐
    │  Trace user inputs through code paths      │
    │  Identify sources and sinks                │
    │  Flag vulnerabilities with context         │
    └─────┬──────────────────────────────────────┘
          │
    8 Contextual Findings
          │
          ▼
    ┌──────────────────────────┐
    │  PHASE 3: LLM Triage     │
    │  (Groq API)              │
    └──────────┬───────────────┘
               │
    ┌──────────▼──────────┐
    │  Confidence Scoring │
    │  (60%+ filter)      │
    └──────────┬──────────┘
               │
         6 High-Confidence
              Findings
               │
               ▼
    ┌──────────────────────────┐
    │  PHASE 4: Batch Fixing   │
    │  & Verification          │
    └──────────┬───────────────┘
               │
    ┌──────────▼───────────────┐
    │  For each vulnerability: │
    │  1. Analyze root cause   │
    │  2. Generate fix (LLM)   │
    │  3. Verify no breakage   │
    │  4. Track attempt        │
    └──────────┬───────────────┘
               │
         Fixed Code Files
               │
               ▼
    ┌──────────────────────────┐
    │  PHASE 5: PR Creation    │
    │  (GitHub Integration)    │
    └──────────┬───────────────┘
               │
    ┌──────────▼──────────────────┐
    │  - Create feature branch    │
    │  - Commit fixes             │
    │  - Push to GitHub           │
    │  - Create PR with report    │
    └──────────┬──────────────────┘
               │
          GitHub Pull Request
          (Ready for Review)
```

## Core Components

### 1. Scanner (`internal/scanner/`)
Responsible for initial vulnerability detection.

**Key Functions:**
- SAST scanning using pattern matching
- Static code analysis
- Configuration file analysis
- Dependency checking

**Output:**
- List of potential vulnerabilities with:
  - Type (SQL Injection, Hardcoded Secret, etc.)
  - File and line number
  - Severity level
  - Code snippet

### 2. Flagging Engine (`internal/flagging/`)
Reduces false positives through intelligent analysis.

**Key Functions:**
- Data flow tracing
- Context-aware analysis
- Vulnerability classification
- Source/sink identification

**Input:** Raw findings from scanners
**Output:** Contextually relevant flags with data flow information

### 3. LLM Triager (`internal/llm/`)
Uses Groq API for intelligent confidence scoring.

**Key Functions:**
- Confidence score generation (0-100%)
- Severity reassessment
- Filter findings by confidence threshold (60%+)
- Generate detailed descriptions

**Input:** Flagged vulnerabilities
**Output:** High-confidence findings with scoring rationale

### 4. Batch Fixer (`internal/fixer/`)
Automatically generates and applies security patches.

**Key Functions:**
- Root cause analysis
- LLM-powered code generation
- Fix verification
- Attempt tracking

**Input:** High-confidence findings + source code
**Output:** Fixed code files with detailed patch reports

### 5. GitHub Client (`internal/github/`)
Handles GitHub integration for PR creation.

**Key Functions:**
- Branch creation
- Commit management
- PR creation with detailed descriptions
- Authentication handling

**Input:** Fixed code files + patch reports
**Output:** Pull request URL

### 6. Config (`internal/config/`)
Centralized configuration management.

**Responsibilities:**
- Load environment variables
- Validate credentials
- Manage plan tiers (free/pro/enterprise)
- Set resource limits

## Data Flow

```
User Input (code path)
    │
    ├─→ Scanner: Detects patterns and anomalies
    │
    ├─→ Flagging: Correlates findings with data flow
    │
    ├─→ LLM Triage: Scores confidence (filter 60%+)
    │
    ├─→ Fixer: Generates and tests patches
    │
    └─→ GitHub: Creates PR with all fixes
```

## Key Design Patterns

### 1. Pipeline Pattern
Each phase is a discrete step with clear inputs/outputs, allowing:
- Parallel processing
- Caching intermediate results
- Rollback capability

### 2. Strategy Pattern
Different scanners implement common interface:
```go
type Scanner interface {
    Scan(fileContent map[string]string) ([]Finding, error)
}
```

### 3. Factory Pattern
Component initialization:
```go
scanner := scanner.NewMultiScanner(userPlan)
triager := llm.NewLLMTriager()
fixer := fixer.NewBatchFixer()
```

## Accuracy & Filtering

### Vulnerability Reduction Through Phases

```
Phase 1 → Phase 2 → Phase 3
  12   →    8    →    6
         -4 (33%)  -2 (25%)

Overall Reduction: 50% false positives eliminated
```

### Why This Works

1. **Phase 1 (Raw Detection)**: Casts wide net, includes noise
2. **Phase 2 (Context)**: Removes findings lacking real data flow
3. **Phase 3 (Confidence)**: AI filters low-probability issues

## Extensibility

### Adding a New Scanner
```go
// 1. Implement Scanner interface
type MyScanner struct {}
func (s *MyScanner) Scan(files map[string]string) ([]Finding, error) {
    // Your scan logic
}

// 2. Register in MultiScanner
scanners := []Scanner{
    &SASTScanner{},
    &MyScanner{},  // ← Add here
}
```

### Adding a New Fixer
```go
// 1. Implement fixer interface
func (f *BatchFixer) fixSQLInjection(finding Flag) (string, error) {
    // Your fix logic
}

// 2. Call in FixFileVulnerabilities
switch finding.Type {
case "SQL_INJECTION":
    return f.fixSQLInjection(finding)
}
```

## Performance Characteristics

| Component | Typical Time | Scalability |
|-----------|-------------|-------------|
| Scanner | 500ms-2s | O(files) |
| Flagging | 200ms-500ms | O(findings) |
| LLM Triage | 1-3s | O(findings) |
| Fixer | 2-5s per file | O(vulns × complexity) |
| GitHub PR | 500ms-1s | O(1) |

**Total for typical repo:** 5-15 seconds

## Security Considerations

1. **API Keys**: Loaded from environment, never logged
2. **Token Handling**: GitHub PAT kept in memory, not persisted
3. **Code Access**: Source code scanned locally, not sent externally
4. **Audit Trail**: All operations logged to `gensec_attempts.log`

## Plan Tier Differences

| Feature | Free | Pro | Enterprise |
|---------|------|-----|------------|
| SAST Scanning | ✅ | ✅ | ✅ |
| Data Flow Flagging | Basic | Full | Full |
| LLM Triage | ❌ | ✅ | ✅ |
| Batch Fixing | Limited | ✅ | ✅ |
| GitHub Integration | ✅ | ✅ | ✅ |
| Priority Support | ❌ | ❌ | ✅ |
| Custom Rules | ❌ | ✅ | ✅ |
| API Access | ❌ | ❌ | ✅ |

## Future Enhancements

1. **Multi-language support** (Python, Java, Rust)
2. **Custom vulnerability rules** (user-defined patterns)
3. **Machine learning** (trained on common vulnerability patterns)
4. **REST API** (for tool integration)
5. **Web dashboard** (visualization of findings)
6. **Incremental scanning** (only modified files)
