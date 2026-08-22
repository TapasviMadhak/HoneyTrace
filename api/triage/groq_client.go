package triage

type GroqClient struct{}

func (g GroqClient) Summarize(event Event) (string, error) {
	return "Groq triage placeholder for event " + event.ID, nil
}
