package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"scanner-external-go/internal/config"
	"scanner-external-go/internal/models"
)

type Client struct {
	uniqueID   string
	authToken  string
	version    string
	apiURL     string
	Limit      int
	httpClient *http.Client
}

func NewClient(cfg *config.Config) *Client {
	return &Client{
		uniqueID:  cfg.UniqueID,
		authToken: cfg.AuthToken,
		version:   cfg.Version,
		apiURL:    cfg.APIUrl,
		Limit:     cfg.Limit,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (c *Client) createRequest(method string, endpoint string, body io.Reader) (*http.Request, error) {
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
	req.Header.Set("app-type", "go")

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

func (c *Client) GetJobs() (*models.JobsResponse, error) {
	endpoint := "external-jobs"
	if c.Limit > 0 {
		params := url.Values{}
		params.Add("limit", strconv.Itoa(c.Limit))
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

	var jobs models.JobsResponse
	if err := json.Unmarshal(body, &jobs); err != nil {
		return nil, err
	}

	return &jobs, nil
}

func (c *Client) SuccessJob(jobID int, results []models.ScanResult) error {
	resultMap := map[string][]models.ScanResult{
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
