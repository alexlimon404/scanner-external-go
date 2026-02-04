package main

import (
	"fmt"
	"os"
	"time"

	"scanner-external-go/internal/api"
	"scanner-external-go/internal/config"
	"scanner-external-go/internal/scanner"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
	}

	client := api.NewClient(cfg)

	scanner.StartContinuousProcessing(client, 40*time.Second)
}
