package triage

type Event struct {
	ID        string
	SourceIP  string
	ActorID   string
	Technique string
	Severity  string
	Message   string
}

type Provider interface {
	Summarize(Event) (string, error)
}
