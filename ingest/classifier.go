package main

func classifyEvent(message string) string {
	switch {
	case message == "":
		return "unknown"
	case contains(message, "failed password"):
		return "bruteforce"
	case contains(message, "scan"):
		return "probe"
	case contains(message, "exploit"):
		return "exploit"
	default:
		return "mixed"
	}
}

func contains(value, token string) bool {
	for i := 0; i+len(token) <= len(value); i++ {
		if value[i:i+len(token)] == token {
			return true
		}
	}
	return false
}
