package scanner

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner-external-go/internal/api"
	"scanner-external-go/internal/models"
)

func scanPort(ip string, port int, timeout time.Duration) *models.ScanResult {
	address := fmt.Sprintf("%s:%d", ip, port)

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(timeout))

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
	} else if writeErr != nil {
		data = fmt.Sprintf("write_error: %v", writeErr)
	} else if readErr != nil {
		data = fmt.Sprintf("read_error: %v", readErr)
	} else {
		data = "empty: 0 bytes read"
	}

	return &models.ScanResult{
		IP:     ip,
		Port:   strconv.Itoa(port),
		Status: 200,
		Data:   data,
	}
}

func ScanPortOnAllIPs(ips []string, port int, timeout time.Duration) []models.ScanResult {
	var results []models.ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	ipChan := make(chan string, len(ips))

	for _, ip := range ips {
		ipChan <- ip
	}
	close(ipChan)

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

func ScanJob(job models.Job) []models.ScanResult {
	var allResults []models.ScanResult
	timeout := time.Duration(job.Payload.Data.Timeout) * time.Second

	fmt.Printf("Starting job %d: %d IPs, %d ports\n", job.ID, len(job.Payload.Data.IPs), len(job.Payload.Data.Ports))

	for portIndex, port := range job.Payload.Data.Ports {
		fmt.Printf("Job %d: Scanning port %d (%d/%d) on %d IPs...\n",
			job.ID, port, portIndex+1, len(job.Payload.Data.Ports), len(job.Payload.Data.IPs))

		startTime := time.Now()
		results := ScanPortOnAllIPs(job.Payload.Data.IPs, port, timeout)
		duration := time.Since(startTime)

		allResults = append(allResults, results...)

		fmt.Printf("Job %d: Port %d completed in %v - found %d open ports\n",
			job.ID, port, duration, len(results))
	}

	return allResults
}

func ProcessJob(client *api.Client, job models.Job) error {
	if job.Type != "check_ips" {
		fmt.Printf("Skipping job %d: unsupported type %s\n", job.ID, job.Type)
		return nil
	}

	startTime := time.Now()

	results := ScanJob(job)

	duration := time.Since(startTime)
	fmt.Printf("Job %d completed in %v: found %d total open ports\n",
		job.ID, duration, len(results))

	err := client.SuccessJob(job.ID, results)
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

func StartContinuousProcessing(client *api.Client, checkInterval time.Duration) {
	fmt.Println("Starting continuous job processing...")
	fmt.Printf("Check interval: %v\n", checkInterval)

	for {
		jobsResponse, err := client.GetJobs()
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
			err := ProcessJob(client, job)
			if err != nil {
				fmt.Printf("Error processing job %d: %v\n", job.ID, err)
			}

			time.Sleep(1 * time.Second)
		}

		fmt.Printf("All jobs completed, checking for new jobs in %v...\n", checkInterval)
		time.Sleep(checkInterval)
	}
}
