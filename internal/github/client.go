package github

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Client struct {
	Token string // GITHUB_TOKEN
	User  string // GITHUB_USER
	Repo  string // GITHUB_REPO, e.g. "shivansh-source/Gensec"
}

type prRequest struct {
	Title string `json:"title"`
	Head  string `json:"head"` // branch name
	Base  string `json:"base"` // base branch, e.g. "main"
	Body  string `json:"body"`
}

type prResponse struct {
	HTMLURL string `json:"html_url"`
	Number  int    `json:"number"`
}

// NewClientFromEnv builds a GitHub client using env vars.
func NewClientFromEnv() (*Client, error) {
	token := os.Getenv("GITHUB_TOKEN")
	user := os.Getenv("GITHUB_USER")
	repo := os.Getenv("GITHUB_REPO") // format: "owner/repo"

	if token == "" {
		return nil, errors.New("GITHUB_TOKEN is not set")
	}
	if user == "" {
		return nil, errors.New("GITHUB_USER is not set")
	}
	if repo == "" {
		return nil, errors.New("GITHUB_REPO is not set (expected owner/repo)")
	}

	return &Client{
		Token: token,
		User:  user,
		Repo:  repo,
	}, nil
}

// CreatePRForCurrentChanges:
//   - checks for uncommitted changes
//   - creates a new branch
//   - commits all changes
//   - pushes to origin
//   - opens a PR on GitHub
func (c *Client) CreatePRForCurrentChanges(baseBranch, prTitle, prBody string) (string, error) {
	if baseBranch == "" {
		baseBranch = "main"
	}

	// 0) Ensure we're in a git repo and have changes
	if err := runCmd("git", "rev-parse", "--is-inside-work-tree"); err != nil {
		return "", fmt.Errorf("not inside a git repo: %w", err)
	}

	statusOut, err := runCmdOutput("git", "status", "--porcelain")
	if err != nil {
		return "", fmt.Errorf("failed to get git status: %w", err)
	}
	if strings.TrimSpace(statusOut) == "" {
		return "", errors.New("no changes to commit; nothing to create PR for")
	}

	// 1) Configure git identity INSIDE the container
	authorName := os.Getenv("GIT_AUTHOR_NAME")
	if authorName == "" {
		authorName = c.User // fallback to GITHUB_USER
	}
	authorEmail := os.Getenv("GIT_AUTHOR_EMAIL")
	if authorEmail == "" {
		authorEmail = c.User + "@users.noreply.github.com"
	}

	if err := runCmd("git", "config", "--global", "user.name", authorName); err != nil {
		return "", fmt.Errorf("failed to set git user.name: %w", err)
	}
	if err := runCmd("git", "config", "--global", "user.email", authorEmail); err != nil {
		return "", fmt.Errorf("failed to set git user.email: %w", err)
	}

	// 2) Create a new branch name
	branchName := fmt.Sprintf("gensec/fix-%d", time.Now().Unix())

	// 3) Create branch from current HEAD
	if err := runCmd("git", "checkout", "-b", branchName); err != nil {
		return "", fmt.Errorf("failed to create branch %s: %w", branchName, err)
	}

	// 4) Add and commit all changes
	ensureGitIgnore()
	if err := runCmd("git", "add", "."); err != nil {
		return "", fmt.Errorf("git add failed: %w", err)
	}

	if err := runCmd("git", "commit", "-m", prTitle); err != nil {
		return "", fmt.Errorf("git commit failed: %w", err)
	}

	// 5) Configure push URL to use token
	pushURL := fmt.Sprintf("https://%s:%s@github.com/%s.git", c.User, c.Token, c.Repo)

	// 6) Push branch to GitHub using token-authenticated URL
	if err := runCmd("git", "push", pushURL, branchName); err != nil {
		return "", fmt.Errorf("git push failed: %w", err)
	}

	// 7) Call GitHub API to create PR
	url := fmt.Sprintf("https://api.github.com/repos/%s/pulls", c.Repo)

	payload := prRequest{
		Title: prTitle,
		Head:  branchName,
		Base:  baseBranch,
		Body:  prBody,
	}

	bodyBytes, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to build PR request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call GitHub API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(resp.Body)
		return "", fmt.Errorf("GitHub API error: %s - %s", resp.Status, buf.String())
	}

	var prResp prResponse
	if err := json.NewDecoder(resp.Body).Decode(&prResp); err != nil {
		return "", fmt.Errorf("failed to decode PR response: %w", err)
	}

	return prResp.HTMLURL, nil
}

// Helpers to run commands

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runCmdOutput(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	return string(out), err
}

func ensureGitIgnore() {
	ignore := []string{
		"attempt_log.json",
		"report_flagged.json",
		"report_semgrep.json",
		"report_trivy.json",
		"gensec_pr_body.md",
	}

	// Track existing lines to avoid duplicates
	existing := map[string]bool{}
	if data, err := os.ReadFile(".gitignore"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				existing[line] = true
			}
		}
	}

	f, _ := os.OpenFile(".gitignore", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()

	for _, entry := range ignore {
		if !existing[entry] {
			_, _ = f.WriteString(entry + "\n")
		}
	}
}
