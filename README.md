# 🤖 GenSec Pro v3 - Autonomous Vulnerability Fixer with Data Flow Flagging

A powerful Go-based security scanning and automated remediation tool that identifies, flags, triages, and fixes vulnerabilities in Go codebases using advanced data flow analysis and LLM-powered decision making.

## 🎯 Overview

GenSec is an autonomous security agent that performs multi-phase vulnerability detection and remediation:

1. **Scanning** - Multi-scanner vulnerability detection
2. **Data Flow Flagging** - Context-aware vulnerability analysis  
3. **LLM Triage** - Confidence scoring using AI (Groq API)
4. **Batch Fixing** - Automated vulnerability remediation
5. **PR Creation** - Automated GitHub pull request generation

## 📋 Features

- **Multi-Scanner Support** - Comprehensive vulnerability detection
- **Data Flow Analysis** - Intelligent flagging of security issues in context
- **LLM-Powered Triage** - AI-based confidence scoring (requires GROQ_API_KEY)
- **Batch Fixing** - Automated remediation with verification
- **GitHub Integration** - Direct PR creation for fixes
- **Plan-Based Scanning** - Free, Pro, and Enterprise tier support
- **One-Command Pipeline** - `scan-and-fix` for complete workflow

## 🚀 Quick Start

### Prerequisites

- **Go 1.24.5+**
- **Groq API Key** (for LLM triage)
- **GitHub PAT** (for PR creation)
- Docker (optional, for containerized scanning)

### Installation

```bash
git clone https://github.com/shivansh-source/gensec.git
cd gensec
go build -o gensec ./cmd/gensec
```
## Environment Setup
```bash
export GROQ_API_KEY=gsk_...                          # Required for scanning
export GITHUB_TOKEN=ghp_...                          # Required for PR creation
export GITHUB_USER=your-github-username              # GitHub username
export GITHUB_REPO=owner/repo-name                   # Target repository
export USER_PLAN=pro                                 # free|pro|enterprise
```
## 📖 Commands
### Scan for Vulnerabilities
bash
gensec scan [path]
Scans Go files for vulnerabilities and generates flagged findings with LLM triage.

### Fix Vulnerabilities
bash
gensec fix
Batch fixes vulnerabilities from previous scan results.

### Create GitHub PR
bash
gensec pr
Creates a pull request on GitHub with all fixes.

### Complete Pipeline
bash
gensec scan-and-fix [path]
Runs the entire workflow: scan → fix → PR creation in one command.

### check Status
bash
gensec status
Displays current scan status and pending findings.

🔄 Workflow
```
Code
┌─────────────┐
│   PHASE 1   │ Multi-Scanner Detection
└──────┬──────┘
       │
       ├─ SAST Scanning
       ├─ Pattern Matching
       └─ Static Analysis
       │
┌──────▼──────┐
│   PHASE 2   │ Data Flow Flagging
└──────┬──────┘
       │
       ├─ Context Analysis
       ├─ Data Flow Tracing
       └─ Vulnerability Classification
       │
┌──────▼──────┐
│   PHASE 3   │ LLM Triage
└──────┬──────┘
       │
       ├─ AI-Powered Scoring
       ├─ Confidence Filtering
       └─ Priority Assignment
       │
┌──────▼──────┐
│   PHASE 4   │ Batch Fixing & Verification
└──────┬──────┘
       │
       ├─ Automated Remediation
       ├─ Code Generation
       └─ Verification
       │
┌──────▼──────┐
│   PHASE 5   │ GitHub PR Creation
└─────────────┘
```
📁 Project Structure
Code
gensec/
├── cmd/
│   └── gensec/
│       └── main.go              # Entry point
├── internal/
│   ├── config/                  # Configuration management
│   ├── scanner/                 # Multi-scanner implementation
│   ├── flagging/                # Data flow flagging engine
│   ├── llm/                      # LLM triage integration
│   ├── fixer/                    # Batch vulnerability fixer
│   └── github/                   # GitHub API client
├── Dockerfile                    # Container support
└── go.mod / go.sum              # Dependencies
🔧 Configuration
Plan Tiers
free - Basic scanning with limited flagging
pro - Enhanced data flow analysis with LLM triage
enterprise - Full feature set with priority support
Report Files
gensec_flags.json - Flagged vulnerabilities after data flow analysis
gensec_pr_body.md - Generated PR description (auto-created by fix phase)
gensec_attempts.log - Attempt tracking log
📦 Dependencies
github.com/joho/godotenv - Environment variable loading
🐳 Docker Support
bash
docker build -t gensec .
docker run -e GROQ_API_KEY=gsk_... -e GITHUB_TOKEN=ghp_... gensec scan-and-fix /scan
🔐 Security Considerations
Keep API keys secure - use environment variables or secrets management
Review generated fixes before merging PRs
Configure branch protections for security-related changes
Monitor GenSec execution logs for suspicious activity
📊 Example Output
Code
## 🚀 GenSec Pro v3 - Data Flow Flagging Scanner
============================================================
Plan: pro
📂 Scan root: .
📁 Loaded 5 files

🔍 Phase 1: Multi-Scanner Detection
✅ SAST Scanner: 12 findings

🔍 Phase 2: Data Flow Flagging  
✅ Flagging Complete: 8 vulnerabilities flagged

🔍 Phase 3: LLM Triage
✅ Triage Complete: 6 high-confidence findings (60%+ confidence)

============================================================
✅ SCAN COMPLETE
============================================================
Total findings (all scanners): 12
After data-flow flagging: 8
After LLM triage (confidence >= 60%): 6
🤝 Contributing
Contributions are welcome! Please ensure:

Code passes Go linting standards
New features include appropriate tests
Security implications are documented
📄 License
See repository for license details.

