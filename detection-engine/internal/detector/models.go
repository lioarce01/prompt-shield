package detector

import "time"

// DetectionRequest represents an incoming prompt analysis request
type DetectionRequest struct {
	Text   string           `json:"text"`
	Config *DetectionConfig `json:"config,omitempty"`
}

// DetectionConfig allows per-request configuration (simplified for LLM-only)
type DetectionConfig struct {
	ConfidenceThreshold float64 `json:"confidence_threshold,omitempty"`
	DetailedResponse    bool    `json:"detailed_response,omitempty"`
}

// DetectionResponse represents the analysis result (simplified for LLM-only)
type DetectionResponse struct {
	IsMalicious      bool     `json:"is_malicious"`
	Confidence       float64  `json:"confidence"`
	ThreatTypes      []string `json:"threat_types"`
	ProcessingTimeMs int64    `json:"processing_time_ms"`
	Reason           string   `json:"reason,omitempty"`
	Endpoint         string   `json:"endpoint,omitempty"`
}

// ThreatType represents different types of prompt injection threats
type ThreatType string

const (
	ThreatTypeJailbreak        ThreatType = "jailbreak"
	ThreatTypeSystemPromptLeak ThreatType = "system_prompt_leak"
	ThreatTypeInjection        ThreatType = "injection"
	ThreatTypeDataExtraction   ThreatType = "data_extraction"
	ThreatTypeEncodingAttack   ThreatType = "encoding_attack"
	ThreatTypeDelimiterAttack  ThreatType = "delimiter_attack"
)

// DetectionMethod represents different detection approaches (LLM-only)
type DetectionMethod string

const (
	MethodLLM DetectionMethod = "llm"
)

// DetectionResult represents the result from LLM detection
type DetectionResult struct {
	Method      DetectionMethod `json:"method"`
	Score       float64         `json:"score"`
	ThreatTypes []ThreatType    `json:"threat_types"`
	Reason      string          `json:"reason,omitempty"`
	Duration    time.Duration   `json:"duration"`
}

// HealthStatus represents the health status of the detection engine (LLM-only)
type HealthStatus struct {
	Status           string        `json:"status"`
	Version          string        `json:"version"`
	Uptime           time.Duration `json:"uptime"`
	RequestsServed   int64         `json:"requests_served"`
	AverageLatency   time.Duration `json:"average_latency_ms"`
	LLMEndpoints     []string      `json:"llm_endpoints"`
	APIKeyConfigured bool          `json:"api_key_configured"`
}
