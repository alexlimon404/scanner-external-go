package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"scanner-external-go/internal/models"
)

// Blacklist опасных паттернов (без жесткого whitelist по требованию)
var dangerousPatterns = []string{
	"rm -rf /",
	"mkfs",
	"dd if=/dev/zero of=/dev/",
	":(){ :|:& };:", // fork bomb
	"chmod -R 777 /",
}

func isCommandSafe(command string) error {
	cmdLower := strings.ToLower(command)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(cmdLower, pattern) {
			return fmt.Errorf("command contains dangerous pattern: %s", pattern)
		}
	}
	return nil
}

func ExecuteCommand(data models.ExecuteCommandData) models.CommandExecutionResult {
	result := models.CommandExecutionResult{}

	// Проверка безопасности
	if err := isCommandSafe(data.Command); err != nil {
		result.Error = fmt.Sprintf("security check failed: %v", err)
		result.ExitCode = -1
		return result
	}

	// Настройка timeout
	timeout := time.Duration(data.Timeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	startTime := time.Now()

	// Создание команды
	shell := data.Shell
	if shell == "" {
		shell = "/bin/bash"
	}

	cmd := exec.CommandContext(ctx, shell, "-c", data.Command)

	// Настройка рабочей директории
	if data.WorkingDir != "" {
		cmd.Dir = data.WorkingDir
	}

	// Настройка переменных окружения
	if len(data.Env) > 0 {
		cmd.Env = []string{}
		for key, value := range data.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
		}
	}

	// Буферы для stdout и stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Выполнение команды
	err := cmd.Run()
	executionTime := time.Since(startTime)

	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	result.ExecutionTimeMs = executionTime.Milliseconds()

	// Обработка результата
	if ctx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		result.ExitCode = -1
		result.Error = "command execution timed out"
	} else if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
		} else {
			result.ExitCode = -1
			result.Error = err.Error()
		}
	} else {
		result.ExitCode = 0
	}

	return result
}

func ProcessCommandJob(job models.Job) (models.CommandExecutionResult, error) {
	// Парсинг данных
	dataBytes, err := json.Marshal(job.Payload.Data)
	if err != nil {
		return models.CommandExecutionResult{
			Error:    fmt.Sprintf("failed to marshal job data: %v", err),
			ExitCode: -1,
		}, err
	}

	var commandData models.ExecuteCommandData
	if err := json.Unmarshal(dataBytes, &commandData); err != nil {
		return models.CommandExecutionResult{
			Error:    fmt.Sprintf("failed to unmarshal command data: %v", err),
			ExitCode: -1,
		}, err
	}

	fmt.Printf("Executing command: %s (timeout: %ds, dir: %s)\n",
		commandData.Command, commandData.Timeout, commandData.WorkingDir)

	result := ExecuteCommand(commandData)

	fmt.Printf("Command completed: exit_code=%d, time=%dms, timed_out=%v\n",
		result.ExitCode, result.ExecutionTimeMs, result.TimedOut)

	return result, nil
}
