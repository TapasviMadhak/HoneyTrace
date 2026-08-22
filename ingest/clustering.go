package main

func clusterActor(sourceIP, hassh, username string) string {
	if hassh != "" && username != "" {
		return "cluster:mixed"
	}
	if hassh != "" {
		return "cluster:hassh"
	}
	if username != "" {
		return "cluster:username"
	}
	return "cluster:unknown"
}
