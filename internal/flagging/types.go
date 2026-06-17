package flagging

type Flag struct {
	VulnID      string
	File        string
	Line        int
	CWE         string
	Severity    string
	Message     string
	Type        string // "SOURCE_TO_SINK", "DATA_FLOW", "RISKY_PATTERN"
	SourceType  string // "URL_PARAM", "FORM_VALUE", "ENV_VAR"
	SinkType    string // "SHELL_COMMAND", "SQL_QUERY", "XSS_OUTPUT"
	Source      string
	Sink        string
	Sanitizer   string
	SourceLine  int
	SinkLine    int
	IsSanitized bool
	Confidence  float64
	CodeContext string
	Explanation string
	Tools       []string
}
