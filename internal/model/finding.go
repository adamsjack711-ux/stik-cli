package model

// Severity ranks a finding by how much it should worry you. It is deliberately
// coarse: five buckets a person can hold in their head, not a CVSS score.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Rank orders severities; higher is worse. Unknown values rank lowest so a
// malformed severity can never masquerade as urgent.
func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	case SevInfo:
		return 0
	}
	return -1
}

// ParseSeverity reads a severity name, for flags like --fail-on high.
func ParseSeverity(s string) (Severity, bool) {
	switch Severity(s) {
	case SevInfo, SevLow, SevMedium, SevHigh, SevCritical:
		return Severity(s), true
	}
	return "", false
}

// Finding is one thing worth telling the operator about, tied to the host (and
// usually the port) that produced it. Evidence is the observed detail the
// finding rests on — the banner line, the certificate subject — so a reader can
// check the claim instead of taking it on trust.
type Finding struct {
	ID       string   `json:"id"`             // stable rule id, e.g. "STIK-A001"
	Host     string   `json:"host"`           // IP the finding is about
	Port     int      `json:"port,omitempty"` // 0 when the finding is host-wide
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
	Evidence string   `json:"evidence,omitempty"`
	Fix      string   `json:"fix,omitempty"`
}
