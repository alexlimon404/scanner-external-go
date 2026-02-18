package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	APIUrl    string
	UniqueID  string
	AuthToken string
	Limit     int
	Version   string
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	limit := 10
	if limitStr := os.Getenv("SCANNER_LIMIT"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil {
			limit = parsed
		}
	}

	return &Config{
		APIUrl:    os.Getenv("SCANNER_API_URL"),
		UniqueID:  os.Getenv("SCANNER_UNIQUE_ID"),
		AuthToken: os.Getenv("SCANNER_AUTH_TOKEN"),
		Limit:     limit,
		Version:   "0.3",
	}, nil
}
