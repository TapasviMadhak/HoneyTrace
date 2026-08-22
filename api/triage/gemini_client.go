package triage

type GeminiClient struct{}

func (g GeminiClient) Summarize(event Event) (string, error) {
	return "Gemini triage placeholder for event " + event.ID, nil
}
