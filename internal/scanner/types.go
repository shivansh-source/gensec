package scanner

type Finding struct {
	Tool       string
	File       string
	Line       int
	CWE        string
	Severity   string
	Message    string
	VulnID     string
	Snippet    string
	Confidence float64
}
