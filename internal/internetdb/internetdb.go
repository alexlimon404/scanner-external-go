package internetdb

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"scanner-external-go/internal/models"
)

const (
	baseURL    = "https://internetdb.shodan.io"
	maxRetries = 3
	retryDelay = 5 * time.Second
	rateDelay  = 1100 * time.Millisecond // чуть больше 1s чтобы не задеть лимит
)

var httpClient = &http.Client{
	Timeout: 5 * time.Second,
}

type apiResponse struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Hostnames []string `json:"hostnames"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
	Cpes      []string `json:"cpes"`
}

// fetchHost возвращает nil если IP не найден (404).
// При 429 делает до maxRetries попыток с паузой retryDelay.
func fetchHost(ip string) *models.InternetDbResult {
	result := &models.InternetDbResult{IP: ip}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		resp, err := httpClient.Get(fmt.Sprintf("%s/%s", baseURL, ip))
		if err != nil {
			result.FetchError = err.Error()
			return result
		}

		status := resp.StatusCode
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if status == 404 {
			return nil
		}

		if status == 429 {
			if attempt < maxRetries {
				time.Sleep(retryDelay)
				continue
			}
			result.FetchError = "HTTP 429"
			return result
		}

		if status != 200 {
			result.FetchError = fmt.Sprintf("HTTP %d", status)
			return result
		}

		var data apiResponse
		if err := json.Unmarshal(body, &data); err != nil {
			result.FetchError = fmt.Sprintf("json: %v", err)
			return result
		}

		result.Ports = data.Ports
		result.Hostnames = data.Hostnames
		result.Tags = data.Tags
		result.Vulns = data.Vulns
		result.Cpes = data.Cpes

		return result
	}

	result.FetchError = "HTTP 429"
	return result
}

func ProcessJob(job models.Job) ([]models.InternetDbResult, models.InternetDbStats, error) {
	dataBytes, err := json.Marshal(job.Payload.Data)
	if err != nil {
		return nil, models.InternetDbStats{}, fmt.Errorf("failed to marshal job data: %v", err)
	}

	var data models.InternetDbData
	if err := json.Unmarshal(dataBytes, &data); err != nil {
		return nil, models.InternetDbStats{}, fmt.Errorf("failed to unmarshal internetdb data: %v", err)
	}

	fmt.Printf("Job %d (internetdb): processing %d IPs (~%ds)\n",
		job.ID, len(data.IPs), len(data.IPs))

	startTime := time.Now()
	var results []models.InternetDbResult
	stats := models.InternetDbStats{Total: len(data.IPs)}

	for i, ip := range data.IPs {
		if i > 0 {
			time.Sleep(rateDelay)
		}

		r := fetchHost(ip)

		if r == nil {
			stats.NotFound++
			fmt.Printf("  [%d/%d] %s → not found\n", i+1, stats.Total, ip)
			continue
		}

		if r.FetchError != "" {
			stats.Errors++
			fmt.Printf("  [%d/%d] %s → error: %s\n", i+1, stats.Total, ip, r.FetchError)
		} else {
			stats.Found++
			fmt.Printf("  [%d/%d] %s → ports: %v\n", i+1, stats.Total, ip, r.Ports)
		}

		results = append(results, *r)
	}

	stats.DurationMs = time.Since(startTime).Milliseconds()

	fmt.Printf("Job %d (internetdb): done — found=%d, not_found=%d, errors=%d, time=%dms\n",
		job.ID, stats.Found, stats.NotFound, stats.Errors, stats.DurationMs)

	return results, stats, nil
}
