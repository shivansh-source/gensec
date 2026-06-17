package fixer

import (
	"encoding/json"
	"os"
	"time"

	"github.com/shivansh-source/gensec/internal/config"
)

type AttemptLog struct {
	VulnID        string    `json:"vuln_id"`
	AttempCount   int       `json:"attempt_count"`
	LastAttempted time.Time `json:"last_attempted"`
	Status        string    `json:"status"` // "new", "failed", "fixed", "escalated"
	Attempts      []Attempt `json:"attempts"`
}

type Attempt struct {
	Number    int       `json:"attempt_number"`
	Status    string    `json:"status"` // "success", "failed"
	Timestamp time.Time `json:"timestamp"`
	Error     string    `json:"error,omitempty"`
}

type AttemptTracker struct {
	logs map[string]*AttemptLog
	file string
}

func NewAttemptTracker() *AttemptTracker {
	tracker := &AttemptTracker{
		logs: make(map[string]*AttemptLog),
		file: config.AttemptLogFile,
	}
	tracker.Load()
	return tracker
}

func (at *AttemptTracker) Load() error {
	data, err := os.ReadFile(at.file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist yet
		}
		return err
	}

	var logs []AttemptLog
	if err := json.Unmarshal(data, &logs); err != nil {
		return err
	}

	for i := range logs {
		at.logs[logs[i].VulnID] = &logs[i]
	}

	return nil
}

func (at *AttemptTracker) Save() error {
	var logs []AttemptLog
	for _, log := range at.logs {
		logs = append(logs, *log)
	}

	data, err := json.MarshalIndent(logs, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(at.file, data, 0644)
}

func (at *AttemptTracker) RecordAttempt(vulnID string, status string, errMsg string) {
	if _, exists := at.logs[vulnID]; !exists {
		at.logs[vulnID] = &AttemptLog{
			VulnID:   vulnID,
			Status:   "new",
			Attempts: []Attempt{},
		}
	}

	log := at.logs[vulnID]
	log.AttempCount++
	log.LastAttempted = time.Now()
	log.Status = status

	log.Attempts = append(log.Attempts, Attempt{
		Number:    log.AttempCount,
		Status:    status,
		Timestamp: time.Now(),
		Error:     errMsg,
	})

	at.Save()
}

func (at *AttemptTracker) GetAttempts(vulnID string) int {
	if log, exists := at.logs[vulnID]; exists {
		return log.AttempCount
	}
	return 0
}

func (at *AttemptTracker) ShouldRetry(vulnID string) bool {
	attempts := at.GetAttempts(vulnID)
	return attempts < config.MaxAttemptsPerVuln
}

func (at *AttemptTracker) MarkEscalated(vulnID string) {
	if _, exists := at.logs[vulnID]; !exists {
		at.logs[vulnID] = &AttemptLog{
			VulnID:   vulnID,
			Status:   "escalated",
			Attempts: []Attempt{},
		}
	}
	at.logs[vulnID].Status = "escalated"
	at.Save()
}
