package fixer

import "github.com/shivansh-source/gensec/internal/flagging"

type FixResult struct {
	File           string
	Status         string // "success", "partial", "failed"
	FixedCode      string
	VulnsFixed     []flagging.Flag
	VulnsFailed    []flagging.Flag
	VulnsEscalated []flagging.Flag
	PRDescription  string
}
