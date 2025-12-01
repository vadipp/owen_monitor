package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Port            int    `yaml:"port"`
	Login           string `yaml:"login"`
	Password        string `yaml:"password"`
	BaseURL         string `yaml:"base_url"`
	PollingInterval int    `yaml:"polling_interval"` // in seconds
	Mapping         []struct {
		Group   string   `yaml:"group"`
		Names   []string `yaml:"names"`
		Timeout int      `yaml:"timeout"`
	} `yaml:"mapping"`
}

type DeviceData struct {
	Name            string    `json:"name"`
	LastOperativeDt time.Time `json:"-"`
}

type DeviceDataRaw struct {
	Name            string      `json:"name"`
	LastOperativeDt interface{} `json:"lastOperative_dt"`
}

type AuthResponse struct {
	Token string `json:"token"`
}

type Service struct {
	config        Config
	client        *http.Client
	token         string
	tokenMutex    sync.RWMutex
	devices       map[string]DeviceData
	devicesMutex  sync.RWMutex
	groupToNames  map[string][]string
	groupToTimeout map[string]int
}

func NewService(config Config) *Service {
	groupToNames := make(map[string][]string)
	groupToTimeout := make(map[string]int)
	for _, m := range config.Mapping {
		groupToNames[m.Group] = m.Names
		groupToTimeout[m.Group] = m.Timeout
	}

	return &Service{
		config:         config,
		client:         &http.Client{Timeout: 30 * time.Second},
		devices:        make(map[string]DeviceData),
		groupToNames:   groupToNames,
		groupToTimeout: groupToTimeout,
	}
}

func (s *Service) getBaseURL() string {
	baseURL := s.config.BaseURL
	if baseURL == "" {
		baseURL = "https://api.owencloud.ru/v1"
	}
	// Remove trailing slash if present
	if len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}
	return baseURL
}

func (s *Service) authenticate() error {
	url := s.getBaseURL() + "/auth/open"
	payload := map[string]string{
		"login":    s.config.Login,
		"password": s.config.Password,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal auth payload: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute auth request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("auth failed with status %d: %s", resp.StatusCode, string(body))
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	s.tokenMutex.Lock()
	s.token = authResp.Token
	s.tokenMutex.Unlock()

	log.Println("Authentication successful")
	return nil
}

func (s *Service) getToken() string {
	s.tokenMutex.RLock()
	defer s.tokenMutex.RUnlock()
	return s.token
}

func (s *Service) fetchDevices() error {
	url := s.getBaseURL() + "/device/index"
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create device request: %w", err)
	}

	token := s.getToken()
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute device request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		log.Println("Token expired, re-authenticating...")
		if err := s.authenticate(); err != nil {
			return fmt.Errorf("re-authentication failed: %w", err)
		}
		// Retry the request with new token - create a new request
		token = s.getToken()
		req, err = http.NewRequest("POST", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create retry device request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err = s.client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to retry device request: %w", err)
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("device request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var devicesRaw []DeviceDataRaw
	if err := json.NewDecoder(resp.Body).Decode(&devicesRaw); err != nil {
		return fmt.Errorf("failed to decode device response: %w", err)
	}

	// Parse and transform the data according to jq command
	// We need to convert Unix timestamp to ISO format
	transformedDevices := make(map[string]DeviceData)
	for _, deviceRaw := range devicesRaw {
		var timestamp time.Time
		switch v := deviceRaw.LastOperativeDt.(type) {
		case float64:
			// Unix timestamp as number
			timestamp = time.Unix(int64(v), 0).UTC()
		case int64:
			timestamp = time.Unix(v, 0).UTC()
		case string:
			// Try parsing as Unix timestamp string
			var unixTime int64
			if _, err2 := fmt.Sscanf(v, "%d", &unixTime); err2 == nil {
				timestamp = time.Unix(unixTime, 0).UTC()
			} else {
				log.Printf("Warning: could not parse timestamp for %s: %v", deviceRaw.Name, err)
				continue
			}
		default:
			log.Printf("Warning: unexpected timestamp type for %s: %T", deviceRaw.Name, v)
			continue
		}

		transformedDevices[deviceRaw.Name] = DeviceData{
			Name:            deviceRaw.Name,
			LastOperativeDt: timestamp,
		}
	}

	s.devicesMutex.Lock()
	s.devices = transformedDevices
	s.devicesMutex.Unlock()

	log.Printf("Fetched %d devices", len(transformedDevices))
	return nil
}

func (s *Service) startPolling() {
	interval := time.Duration(s.config.PollingInterval) * time.Second
	if interval <= 0 {
		interval = 1 * time.Minute // Default to 1 minute if not configured or invalid
		log.Printf("Warning: polling_interval not configured or invalid, using default: 1 minute")
	}
	
	ticker := time.NewTicker(interval)
	log.Printf("Starting polling with interval: %v", interval)
	go func() {
		// Initial fetch
		if err := s.fetchDevices(); err != nil {
			log.Printf("Error fetching devices: %v", err)
		}
		for range ticker.C {
			if err := s.fetchDevices(); err != nil {
				log.Printf("Error fetching devices: %v", err)
			}
		}
	}()
}

type SourceStatus struct {
	Name           string `json:"name"`
	LastOperative  string `json:"last_operative"`
	Status         string `json:"status"`
}

type StatusResponse struct {
	Sources []SourceStatus `json:"sources"`
}

type GroupsResponse struct {
	Groups []string `json:"groups"`
}

func (s *Service) handleStatusList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get all group names
	groups := make([]string, 0, len(s.groupToNames))
	for group := range s.groupToNames {
		groups = append(groups, group)
	}

	response := GroupsResponse{Groups: groups}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract group from path (e.g., /status/test -> test)
	path := r.URL.Path
	if len(path) <= len("/status/") {
		http.Error(w, "Group is required", http.StatusBadRequest)
		return
	}
	group := path[len("/status/"):]
	if group == "" {
		http.Error(w, "Group is required", http.StatusBadRequest)
		return
	}

	names, exists := s.groupToNames[group]
	if !exists {
		http.Error(w, "Group not found", http.StatusNotFound)
		return
	}

	timeout, exists := s.groupToTimeout[group]
	if !exists {
		http.Error(w, "Timeout not configured", http.StatusInternalServerError)
		return
	}

	s.devicesMutex.RLock()
	defer s.devicesMutex.RUnlock()

	now := time.Now().UTC()
	var sources []SourceStatus
	anyOK := false

	for _, name := range names {
		device, found := s.devices[name]
		if !found {
			// Device data not available - mark as timeout
			sources = append(sources, SourceStatus{
				Name:          name,
				LastOperative: "",
				Status:        "TIMEOUT",
			})
			continue
		}

		// Format timestamp in ISO format
		lastOperativeISO := device.LastOperativeDt.Format("2006-01-02T15:04:05Z")

		// Check if the timestamp is within the timeout
		age := now.Sub(device.LastOperativeDt)
		status := "TIMEOUT"
		if age.Seconds() <= float64(timeout) {
			status = "OK"
			anyOK = true
		}

		sources = append(sources, SourceStatus{
			Name:          name,
			LastOperative: lastOperativeISO,
			Status:        status,
		})
	}

	// Set response status: 200 OK if any device is OK, otherwise 408 Request Timeout
	response := StatusResponse{Sources: sources}
	w.Header().Set("Content-Type", "application/json")
	if anyOK {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusRequestTimeout)
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func main() {
	// Read config file
	configFile, err := os.Open("config.yaml")
	if err != nil {
		log.Fatalf("Failed to open config file: %v", err)
	}
	defer configFile.Close()

	var config Config
	decoder := yaml.NewDecoder(configFile)
	if err := decoder.Decode(&config); err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}

	// Validate config
	if config.Port == 0 {
		log.Fatal("Port must be specified in config.yaml")
	}
	if config.Login == "" || config.Password == "" {
		log.Fatal("Login and password must be specified in config.yaml")
	}

	// Create service
	service := NewService(config)

	// Authenticate on startup
	if err := service.authenticate(); err != nil {
		log.Fatalf("Failed to authenticate: %v", err)
	}

	// Start background polling
	service.startPolling()

	// Setup HTTP server
	// Register /status first (exact match) before /status/ (prefix match)
	http.HandleFunc("/status", service.handleStatusList)
	http.HandleFunc("/status/", service.handleStatus)

	addr := fmt.Sprintf(":%d", config.Port)
	log.Printf("Starting server on port %d", config.Port)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

