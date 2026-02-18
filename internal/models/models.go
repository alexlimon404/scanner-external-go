package models

type Job struct {
	ID      int        `json:"id"`
	TaskID  int        `json:"task_id"`
	Type    string     `json:"type"`
	Payload JobPayload `json:"payload"`
}

type JobPayload struct {
	Data interface{} `json:"data"`
}

// CheckIpsData используется для type = "check_ips"
type CheckIpsData struct {
	IPs     []string `json:"ips"`
	Ports   []int    `json:"ports"`
	Length  int      `json:"length"`
	Timeout int      `json:"timeout"`
}

// ExecuteCommandData используется для type = "execute_command"
type ExecuteCommandData struct {
	Command    string            `json:"command"`
	WorkingDir string            `json:"working_dir"`
	Timeout    int               `json:"timeout"`
	Shell      string            `json:"shell"`
	Env        map[string]string `json:"env"`
}

type JobsResponseMeta struct {
	PollInterval int `json:"poll_interval"`
}

type JobsResponse struct {
	Data []Job            `json:"data"`
	Meta JobsResponseMeta `json:"meta"`
}

type ScanResult struct {
	IP     string `json:"ip"`
	Port   string `json:"port"`
	Status int    `json:"status"`
	Data   string `json:"data"`
}

// CommandExecutionResult используется для результатов выполнения команд
type CommandExecutionResult struct {
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	ExitCode        int    `json:"exit_code"`
	ExecutionTimeMs int64  `json:"execution_time_ms"`
	TimedOut        bool   `json:"timed_out"`
	Error           string `json:"error,omitempty"`
}
