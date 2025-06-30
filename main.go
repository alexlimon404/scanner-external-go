package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Client struct {
	uniqueID   string
	authToken  string
	version    string
	apiURL     string
	limit      int
	httpClient *http.Client
}

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

func NewClient(uniqueID, authToken, version, apiURL string, limit int) *Client {
	return &Client{
		uniqueID:  uniqueID,
		authToken: authToken,
		version:   version,
		apiURL:    apiURL,
		limit:     limit,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (c *Client) createRequest(method, endpoint string, body io.Reader) (*http.Request, error) {
	url := fmt.Sprintf("%s/api/%s", c.apiURL, endpoint)

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("unique", c.uniqueID)
	req.Header.Set("token", c.authToken)
	req.Header.Set("app-version", c.version)
	req.Header.Set("app-type", "lumen")

	return req, nil
}

func (c *Client) doRequest(req *http.Request) ([]byte, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP error: %d %s", resp.StatusCode, resp.Status)
	}

	return io.ReadAll(resp.Body)
}

func (c *Client) GetJobs() (*JobsResponse, error) {
	endpoint := "external-jobs"
	if c.limit > 0 {
		params := url.Values{}
		params.Add("limit", strconv.Itoa(c.limit))
		endpoint = fmt.Sprintf("%s?%s", endpoint, params.Encode())
	}

	req, err := c.createRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var jobs JobsResponse
	if err := json.Unmarshal(body, &jobs); err != nil {
		return nil, err
	}

	return &jobs, nil
}

func (c *Client) SuccessJob(jobID int, results []ScanResult) error {
	resultMap := map[string][]ScanResult{
		strconv.Itoa(jobID): results,
	}

	payload := map[string]interface{}{
		"data": resultMap,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := c.createRequest("POST", "external-jobs", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	_, err = c.doRequest(req)
	return err
}

func scanPort(ip string, port int, timeout time.Duration) *ScanResult {
	address := fmt.Sprintf("%s:%d", ip, port)

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil // Порт закрыт или недоступен
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	httpRequest := "GET / HTTP/1.0\r\n\r\n"
	_, writeErr := conn.Write([]byte(httpRequest))

	buffer := make([]byte, 4096)
	n, readErr := conn.Read(buffer)

	var data string
	if writeErr == nil && readErr == nil && n > 0 {
		data = strings.TrimSpace(string(buffer[:n]))
		data = strings.Map(func(r rune) rune {
			if r >= 32 && r <= 126 || r == '\n' || r == '\r' || r == '\t' {
				return r
			}
			return -1
		}, data)
	} else {
		data = "empty"
	}

	return &ScanResult{
		IP:     ip,
		Port:   strconv.Itoa(port),
		Status: 200,
		Data:   data,
	}
}

func (c *Client) scanPortOnAllIPs(ips []string, port int, timeout time.Duration) []ScanResult {
	var results []ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	ipChan := make(chan string, len(ips))

	for _, ip := range ips {
		ipChan <- ip
	}
	close(ipChan)

	// Используем максимальное количество воркеров для одной задачи
	numWorkers := len(ips)
	if numWorkers > 400 {
		numWorkers = 400
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				if result := scanPort(ip, port, timeout); result != nil {
					mu.Lock()
					results = append(results, *result)
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()
	return results
}

func (c *Client) scanJob(job Job) []ScanResult {
	var allResults []ScanResult
	timeout := time.Duration(job.Payload.Data.Timeout) * time.Second

	fmt.Printf("Starting job %d: %d IPs, %d ports\n", job.ID, len(job.Payload.Data.IPs), len(job.Payload.Data.Ports))

	for portIndex, port := range job.Payload.Data.Ports {
		fmt.Printf("Job %d: Scanning port %d (%d/%d) on %d IPs...\n",
			job.ID, port, portIndex+1, len(job.Payload.Data.Ports), len(job.Payload.Data.IPs))

		startTime := time.Now()
		results := c.scanPortOnAllIPs(job.Payload.Data.IPs, port, timeout)
		duration := time.Since(startTime)

		allResults = append(allResults, results...)

		fmt.Printf("Job %d: Port %d completed in %v - found %d open ports\n",
			job.ID, port, duration, len(results))
	}

	return allResults
}

func (c *Client) processJobSequentially(job Job) error {
	if job.Type != "check_ips" {
		fmt.Printf("Skipping job %d: unsupported type %s\n", job.ID, job.Type)
		return nil
	}

	startTime := time.Now()

	results := c.scanJob(job)

	duration := time.Since(startTime)
	fmt.Printf("Job %d completed in %v: found %d total open ports\n",
		job.ID, duration, len(results))

	err := c.SuccessJob(job.ID, results)
	if err != nil {
		return fmt.Errorf("failed to send results for job %d: %v", job.ID, err)
	}

	if len(results) > 0 {
		fmt.Printf("Results for job %d sent successfully (%d results)\n", job.ID, len(results))
	} else {
		fmt.Printf("Empty results for job %d sent successfully\n", job.ID)
	}

	return nil
}

func (c *Client) StartContinuousProcessing(checkInterval time.Duration) {
	fmt.Println("Starting continuous job processing...")
	fmt.Printf("Check interval: %v\n", checkInterval)

	for {
		jobsResponse, err := c.GetJobs()
		if err != nil {
			fmt.Printf("Error getting jobs: %v\n", err)
			time.Sleep(checkInterval)
			continue
		}

		if len(jobsResponse.Data) == 0 {
			fmt.Printf("No jobs available, waiting %v...\n", checkInterval)
			time.Sleep(checkInterval)
			continue
		}

		fmt.Printf("Received %d jobs\n", len(jobsResponse.Data))

		for _, job := range jobsResponse.Data {
			err := c.processJobSequentially(job)
			if err != nil {
				fmt.Printf("Error processing job %d: %v\n", job.ID, err)
			}

			time.Sleep(1 * time.Second)
		}

		fmt.Printf("All jobs completed, checking for new jobs in %v...\n", checkInterval)
		time.Sleep(checkInterval)
	}
}

func main() {

	env := godotenv.Load()
	if env != nil {
		fmt.Print(env)
	}
	client := NewClient(
		string(os.Getenv("SCANNER_UNIQUE_ID")),
		string(os.Getenv("SCANNER_AUTH_TOKEN")),
		"0.1",
		string(os.Getenv("SCANNER_API_URL")),
		10,
	)

	client.StartContinuousProcessing(40 * time.Second)
}
