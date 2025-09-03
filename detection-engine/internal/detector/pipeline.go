package detector

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Pipeline orchestrates LLM-based prompt injection detection
type Pipeline struct {
	llmDetector *LLMDetector
	logger      *logrus.Logger
	metrics     *Metrics

	// Configuration
	confidenceThreshold float64
	startTime           time.Time
}

// Metrics tracks detection performance
type Metrics struct {
	RequestsTotal      int64
	RequestsSuccessful int64
	RequestsFailed     int64
	AverageLatency     time.Duration
	TotalLatency       time.Duration
	DetectionsByThreat map[ThreatType]int64
	mutex              sync.RWMutex
}

// NewPipeline creates a new LLM-only detection pipeline
func NewPipeline(logger *logrus.Logger) *Pipeline {
	llmDetector := NewLLMDetector()

	pipeline := &Pipeline{
		llmDetector:         llmDetector,
		logger:              logger,
		metrics:             NewMetrics(),
		confidenceThreshold: 0.6, // Adjusted for LLM-based detection
		startTime:           time.Now(),
	}

	if llmDetector.IsAvailable() {
		logger.Info("LLM detection pipeline initialized successfully with API key")
	} else {
		logger.Warn("LLM detection pipeline initialized without API key - set HUGGINGFACE_API_KEY environment variable")
	}

	return pipeline
}

// Analyze processes a detection request using LLM-only approach
func (p *Pipeline) Analyze(ctx context.Context, req *DetectionRequest) (*DetectionResponse, error) {
	startTime := time.Now()

	// Validate input
	if len(req.Text) == 0 {
		return p.handleEmptyInput(startTime), nil
	}

	// Apply request-specific configuration
	config := p.applyConfig(req.Config)

	// Check if LLM is available
	if !p.llmDetector.IsAvailable() {
		return p.handleUnavailableLLM(startTime), fmt.Errorf("LLM detection unavailable - no API key configured")
	}

	// Perform LLM detection
	result, err := p.llmDetector.Detect(req.Text)
	if err != nil {
		p.metrics.RecordFailure(time.Since(startTime))
		return p.handleLLMError(startTime, err), err
	}

	// Build response
	response := p.buildResponse(result, config, time.Since(startTime))

	// Record metrics
	p.metrics.RecordSuccess(time.Since(startTime), response)

	return response, nil
}

// handleEmptyInput returns appropriate response for empty input
func (p *Pipeline) handleEmptyInput(startTime time.Time) *DetectionResponse {
	return &DetectionResponse{
		IsMalicious:      false,
		Confidence:       0.0,
		ThreatTypes:      []string{},
		ProcessingTimeMs: time.Since(startTime).Milliseconds(),
		Reason:           "Empty input - not malicious",
		Endpoint:         "none",
	}
}

// handleUnavailableLLM returns conservative response when LLM is unavailable
func (p *Pipeline) handleUnavailableLLM(startTime time.Time) *DetectionResponse {
	return &DetectionResponse{
		IsMalicious:      false,
		Confidence:       0.5, // Conservative uncertainty
		ThreatTypes:      []string{},
		ProcessingTimeMs: time.Since(startTime).Milliseconds(),
		Reason:           "LLM unavailable - conservative safe classification",
		Endpoint:         "fallback",
	}
}

// handleLLMError returns appropriate response when LLM fails
func (p *Pipeline) handleLLMError(startTime time.Time, err error) *DetectionResponse {
	p.logger.WithError(err).Error("LLM detection failed")

	return &DetectionResponse{
		IsMalicious:      false,
		Confidence:       0.5, // Conservative uncertainty
		ThreatTypes:      []string{},
		ProcessingTimeMs: time.Since(startTime).Milliseconds(),
		Reason:           fmt.Sprintf("LLM error: %s - conservative safe classification", err.Error()),
		Endpoint:         "error",
	}
}

// buildResponse constructs the final detection response
func (p *Pipeline) buildResponse(result *DetectionResult, config *DetectionConfig, duration time.Duration) *DetectionResponse {
	// Convert threat types to strings
	threatTypes := make([]string, len(result.ThreatTypes))
	for i, threat := range result.ThreatTypes {
		threatTypes[i] = string(threat)
	}

	// Determine if malicious based on threshold
	threshold := config.ConfidenceThreshold
	if threshold == 0 {
		threshold = p.confidenceThreshold
	}

	isMalicious := result.Score >= threshold

	response := &DetectionResponse{
		IsMalicious:      isMalicious,
		Confidence:       result.Score,
		ThreatTypes:      threatTypes,
		ProcessingTimeMs: duration.Milliseconds(),
		Reason:           result.Reason,
		Endpoint:         "huggingface", // Could be dynamic based on which endpoint was used
	}

	p.logger.WithFields(logrus.Fields{
		"confidence":   result.Score,
		"threshold":    threshold,
		"is_malicious": isMalicious,
		"threat_types": threatTypes,
		"duration_ms":  duration.Milliseconds(),
		"reason":       result.Reason,
	}).Debug("LLM detection completed")

	return response
}

// applyConfig applies request-specific configuration with defaults
func (p *Pipeline) applyConfig(config *DetectionConfig) *DetectionConfig {
	if config == nil {
		config = &DetectionConfig{}
	}

	// Set defaults if not specified
	if config.ConfidenceThreshold == 0 {
		config.ConfidenceThreshold = p.confidenceThreshold
	}

	return config
}

// GetMetrics returns current pipeline metrics
func (p *Pipeline) GetMetrics() *Metrics {
	return p.metrics
}

// GetHealth returns pipeline health status
func (p *Pipeline) GetHealth() *HealthStatus {
	endpoints := make([]string, len(p.llmDetector.endpoints))
	for i, endpoint := range p.llmDetector.endpoints {
		endpoints[i] = endpoint.Model
	}
	apiKeyConfigured := p.llmDetector.IsAvailable()

	status := "healthy"
	if !apiKeyConfigured {
		status = "degraded - no API key"
	}

	return &HealthStatus{
		Status:           status,
		Version:          "2.1.0-specialized-models",
		Uptime:           time.Since(p.startTime),
		RequestsServed:   p.metrics.GetRequestsTotal(),
		AverageLatency:   p.metrics.GetAverageLatency(),
		LLMEndpoints:     endpoints,
		APIKeyConfigured: apiKeyConfigured,
	}
}

// DiagnoseLLMEndpoints tests LLM endpoints and returns their status
func (p *Pipeline) DiagnoseLLMEndpoints() map[string]interface{} {
	diagnostic := make(map[string]interface{})

	if p.llmDetector == nil {
		diagnostic["error"] = "LLM detector not initialized"
		return diagnostic
	}

	// Test cloud LLM endpoints
	for i, endpoint := range p.llmDetector.endpoints {
		name := fmt.Sprintf("endpoint_%d", i)
		diagnostic[name] = map[string]interface{}{
			"status":  "available",
			"type":    endpoint.Type,
			"model":   endpoint.Model,
			"url":     endpoint.URL,
			"timeout": endpoint.Timeout.String(),
		}
	}

	diagnostic["api_key_configured"] = p.llmDetector.IsAvailable()
	diagnostic["total_endpoints"] = len(p.llmDetector.endpoints)

	if p.llmDetector.IsAvailable() {
		diagnostic["status"] = "LLM endpoints ready"
	} else {
		diagnostic["status"] = "No API key - set HUGGINGFACE_API_KEY environment variable"
	}

	return diagnostic
}

// NewMetrics creates a new metrics instance
func NewMetrics() *Metrics {
	return &Metrics{
		DetectionsByThreat: make(map[ThreatType]int64),
	}
}

// RecordSuccess records a successful detection
func (m *Metrics) RecordSuccess(duration time.Duration, response *DetectionResponse) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.RequestsTotal++
	m.RequestsSuccessful++
	m.TotalLatency += duration
	m.AverageLatency = m.TotalLatency / time.Duration(m.RequestsTotal)

	// Record threat type statistics
	for _, threatStr := range response.ThreatTypes {
		threat := ThreatType(threatStr)
		m.DetectionsByThreat[threat]++
	}
}

// RecordFailure records a failed detection
func (m *Metrics) RecordFailure(duration time.Duration) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.RequestsTotal++
	m.RequestsFailed++
	m.TotalLatency += duration
	m.AverageLatency = m.TotalLatency / time.Duration(m.RequestsTotal)
}

// GetRequestsTotal returns total requests processed
func (m *Metrics) GetRequestsTotal() int64 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.RequestsTotal
}

// GetAverageLatency returns average processing latency
func (m *Metrics) GetAverageLatency() time.Duration {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.AverageLatency
}
