package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	BaseURL        string
	AssetUpstream  string
	IssuesUpstream string
	APIKey         string
	HTTPClient     *http.Client
}

func NewClient(baseURL, apiKey string) *Client {
	return NewClientWithUpstreams(baseURL, "", "", apiKey)
}

func NewClientWithUpstreams(baseURL, assetUpstream, issuesUpstream, apiKey string) *Client {
	return &Client{
		BaseURL:        baseURL,
		AssetUpstream:  assetUpstream,
		IssuesUpstream: issuesUpstream,
		APIKey:         apiKey,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// resolveEndpoint constructs the full target URL based on an upstream prefix (relative or absolute) and an endpoint
func (c *Client) resolveEndpoint(upstream, endpoint string) string {
	target := upstream
	if target == "" {
		target = c.BaseURL
	} else if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		// Relative path: prefix with BaseURL
		target = strings.TrimRight(c.BaseURL, "/") + "/" + strings.TrimLeft(target, "/")
	}

	return strings.TrimRight(target, "/") + "/" + strings.TrimLeft(endpoint, "/")
}

func (c *Client) getAssetTarget() string {
	if c.AssetUpstream != "" {
		return c.AssetUpstream
	}
	return c.BaseURL
}

func (c *Client) getIssuesTarget() string {
	if c.IssuesUpstream != "" {
		return c.IssuesUpstream
	}
	if c.AssetUpstream != "" {
		return c.AssetUpstream
	}
	return c.BaseURL
}

type RegisterResponse struct {
	AgentID string `json:"agent_id"`
}

// Register registers the agent with the asset inventory upstream.
func (c *Client) Register(hostname, os, version, ipAddress, architecture, arch string, inventory interface{}) (string, error) {
	data := map[string]interface{}{
		"hostname":     hostname,
		"os":           os,
		"version":      version,
		"ipAddress":    ipAddress,
		"architecture": architecture,
		"arch":         arch,
		"api_key":      c.APIKey,
	}
	if inventory != nil {
		data["data"] = inventory
	}

	url := c.resolveEndpoint(c.getAssetTarget(), "/register")
	respBody, err := c.postToURLWithResponse(url, data)
	if err != nil {
		return "", err
	}

	var regResp RegisterResponse
	if err := json.Unmarshal(respBody, &regResp); err != nil {
		return "", fmt.Errorf("failed to parse registration response (body: %s): %w", string(respBody), err)
	}

	if regResp.AgentID == "" {
		return "", fmt.Errorf("registration failed: agent_id not returned (body: %s)", string(respBody))
	}

	return regResp.AgentID, nil
}

// Heartbeat sends a periodic heartbeat ping to the asset inventory upstream.
func (c *Client) Heartbeat(agentID, version string) (*ResultsResponse, error) {
	data := map[string]string{
		"agent_id":  agentID,
		"version":   version,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	url := c.resolveEndpoint(c.getAssetTarget(), "/heartbeat")
	respBody, err := c.postToURLWithResponse(url, data)
	if err != nil {
		return nil, err
	}

	var res ResultsResponse
	if err := json.Unmarshal(respBody, &res); err != nil {
		return nil, fmt.Errorf("failed to parse heartbeat response (body: %s): %w", string(respBody), err)
	}

	return &res, nil
}

type HTTPError struct {
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("backend returned status: %d, body: %s", e.StatusCode, e.Body)
}

type ScanTargets struct {
	IncludeDirs []string `json:"includeDirs,omitempty"`
	ExcludeDirs []string `json:"excludeDirs,omitempty"`
}

type ScanAgentConfig struct {
	Enabled     bool        `json:"enabled"`
	Version     string      `json:"version"`
	DownloadURL string      `json:"download_url"`
	Interval    int         `json:"interval"` // in seconds
	Targets     ScanTargets `json:"targets,omitempty"`
	BackendURL  string      `json:"backend_url,omitempty"`
}

type AgentSectionConfig struct {
	Enabled       bool   `json:"enabled"`
	Version       string `json:"version"`
	DownloadURL   string `json:"download_url"`
	UpdateChannel string `json:"update_channel"`
}

type InventorySectionConfig struct {
	Enabled  bool `json:"enabled"`
	Interval int  `json:"interval"`
}

type CommunicationSectionConfig struct {
	BackendURL        string `json:"backend_url"`
	AssetUpstream     string `json:"asset_upstream"`
	IssuesUpstream    string `json:"issues_upstream"`
	HeartbeatInterval int    `json:"heartbeat_interval"`
}

type AgentConfiguration struct {
	Kill              bool                        `json:"kill"`
	HeartbeatInterval int                         `json:"heartbeat_interval"` // in seconds
	AssetPushInterval int                         `json:"asset_push_interval"` // in seconds
	LatestVersion     string                      `json:"latest_version"`
	DownloadURL       string                      `json:"download_url"`
	BackendURL        string                      `json:"backend_url,omitempty"`
	AssetUpstream     string                      `json:"asset_upstream,omitempty"`
	IssuesUpstream    string                      `json:"issues_upstream,omitempty"`
	ScanAgent         *ScanAgentConfig            `json:"scan_agent,omitempty"`
	Agent             *AgentSectionConfig         `json:"agent,omitempty"`
	Inventory         *InventorySectionConfig     `json:"inventory,omitempty"`
	Communication     *CommunicationSectionConfig `json:"communication,omitempty"`
}

type ResultsResponse struct {
	Configuration AgentConfiguration `json:"configuration"`
}

type VulnScanConfig struct {
	Enabled  *bool `json:"enabled,omitempty"`
	Interval int   `json:"interval,omitempty"`
}

type VulnConfiguration struct {
	Enabled               *bool           `json:"enabled,omitempty"`
	Interval              int             `json:"interval,omitempty"`
	Frequency             string          `json:"frequency,omitempty"`
	VulnerabilityScanning *VulnScanConfig `json:"vulnerability_scanning,omitempty"`
}

type VulnHeartbeatResponse struct {
	Success       bool              `json:"success"`
	Message       string            `json:"message"`
	Configuration VulnConfiguration `json:"configuration"`
}

// VulnHeartbeat sends a periodic heartbeat ping to the vulnerability upstream.
func (c *Client) VulnHeartbeat(agentID, version string) (*VulnHeartbeatResponse, error) {
	data := map[string]string{
		"agent_id":  agentID,
		"agentId":   agentID,
		"version":   version,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	url := c.resolveEndpoint(c.getIssuesTarget(), "/heartbeat")
	respBody, err := c.postToURLWithResponse(url, data)
	if err != nil {
		return nil, err
	}

	var res VulnHeartbeatResponse
	if err := json.Unmarshal(respBody, &res); err != nil {
		return nil, fmt.Errorf("failed to parse vuln heartbeat response (body: %s): %w", string(respBody), err)
	}

	return &res, nil
}

// SendResults sends asset inventory results to the asset upstream
func (c *Client) SendResults(agentID string, results interface{}) (*ResultsResponse, error) {
	data := map[string]interface{}{
		"agent_id": agentID,
		"data":     results,
	}

	url := c.resolveEndpoint(c.getAssetTarget(), "/results")
	respBody, err := c.postToURLWithResponse(url, data)
	if err != nil {
		return nil, err
	}

	var res ResultsResponse
	if err := json.Unmarshal(respBody, &res); err != nil {
		return nil, fmt.Errorf("failed to parse results response (body: %s): %w", string(respBody), err)
	}

	return &res, nil
}

// SendVulnerabilities reports detected host issues and vulnerabilities to the issues upstream
func (c *Client) SendVulnerabilities(agentID string, findings interface{}) (*ResultsResponse, error) {
	data := map[string]interface{}{
		"agent_id":        agentID,
		"vulnerabilities": findings,
		"data": map[string]interface{}{
			"vulnerabilities": findings,
		},
	}

	url := c.resolveEndpoint(c.getIssuesTarget(), "/results")
	respBody, err := c.postToURLWithResponse(url, data)
	if err != nil {
		return nil, err
	}

	var res ResultsResponse
	if err := json.Unmarshal(respBody, &res); err != nil {
		return nil, fmt.Errorf("failed to parse vulnerabilities response (body: %s): %w", string(respBody), err)
	}

	return &res, nil
}

// SendResultsWithVulnerabilities posts asset inventory to asset upstream and issue findings to issues upstream
func (c *Client) SendResultsWithVulnerabilities(agentID string, results interface{}, findings interface{}) (*ResultsResponse, error) {
	assetRes, err := c.SendResults(agentID, results)
	if err != nil {
		return nil, fmt.Errorf("failed to send asset results to asset upstream: %w", err)
	}

	if findings != nil {
		if _, vulnErr := c.SendVulnerabilities(agentID, findings); vulnErr != nil {
			log.Printf("[Client] Warning: failed to send findings to issues upstream: %v", vulnErr)
		}
	}

	return assetRes, nil
}

func (c *Client) post(endpoint string, data interface{}) error {
	_, err := c.postWithResponse(endpoint, data)
	return err
}

func (c *Client) postWithResponse(endpoint string, data interface{}) ([]byte, error) {
	url := c.resolveEndpoint(c.getAssetTarget(), endpoint)
	return c.postToURLWithResponse(url, data)
}

func (c *Client) postToURLWithResponse(fullURL string, data interface{}) ([]byte, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	maxRetries := 3
	backoff := 2 * time.Second

	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(jsonData))
		if err != nil {
			return nil, err
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", c.APIKey)

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = err
		} else {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				lastErr = err
			} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				httpErr := &HTTPError{StatusCode: resp.StatusCode, Body: string(body)}
				// Do not retry client errors (4xx, e.g. 404 Not Found), return immediately
				if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
					return nil, httpErr
				}
				lastErr = httpErr
			} else {
				return body, nil
			}
		}

		if i < maxRetries {
			log.Printf("Request to %s failed: %v. Retrying in %v (attempt %d/%d)...", fullURL, lastErr, backoff, i+1, maxRetries)
			time.Sleep(backoff)
			backoff *= 2
		}
	}

	return nil, fmt.Errorf("request to %s failed after %d retries: %w", fullURL, maxRetries, lastErr)
}
