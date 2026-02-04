package models

type Job struct {
	ID      int        `json:"id"`
	TaskID  int        `json:"task_id"`
	Type    string     `json:"type"`
	Payload JobPayload `json:"payload"`
}

type JobPayload struct {
	Data JobData `json:"data"`
}

type JobData struct {
	IPs     []string `json:"ips"`
	Ports   []int    `json:"ports"`
	Length  int      `json:"length"`
	Timeout int      `json:"timeout"`
}

type JobsResponse struct {
	Data []Job `json:"data"`
}

type ScanResult struct {
	IP     string `json:"ip"`
	Port   string `json:"port"`
	Status int    `json:"status"`
	Data   string `json:"data"`
}
