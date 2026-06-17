package llm

type TriageResult struct {
	IsReal      bool    `json:"is_real"`
	Confidence  float64 `json:"confidence"`
	Explanation string  `json:"explanation"`
}
