package detector

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"prompt-injection-detection/internal/metrics"
)

// FallbackPipeline orchestrates multiple AI models with circuit breaker fallback
type FallbackPipeline struct {
	modelRegistry     *ModelRegistry
	circuitBreakers   map[string]*CircuitBreaker
	llmDetector       *LLMDetector
	logger            *logrus.Logger
	metrics           *Metrics
	metricsCollector  *metrics.MetricsCollector

	// Configuration
	confidenceThreshold float64
	startTime           time.Time
}

// NewFallbackPipeline creates a new pipeline with circuit breaker fallback system
func NewFallbackPipeline(logger *logrus.Logger) *FallbackPipeline {
	modelRegistry := NewModelRegistry()
	llmDetector := NewLLMDetector()
	
	pipeline := &FallbackPipeline{
		modelRegistry:       modelRegistry,
		circuitBreakers:     make(map[string]*CircuitBreaker),
		llmDetector:         llmDetector,
		logger:              logger,
		metrics:             NewMetrics(),
		metricsCollector:    metrics.NewMetricsCollector(),
		confidenceThreshold: 0.6,
		startTime:           time.Now(),
	}

	// Initialize circuit breakers for each enabled model
	pipeline.initializeCircuitBreakers()

	logger.Info("Fallback pipeline initialized with circuit breakers")
	pipeline.logModelStatus()

	return pipeline
}

// initializeCircuitBreakers creates circuit breakers for all enabled models
func (p *FallbackPipeline) initializeCircuitBreakers() {
	enabledModels := p.modelRegistry.GetEnabledModels()
	
	for _, model := range enabledModels {
		cbConfig := CircuitBreakerConfig{
			Name:             model.Name,
			FailureThreshold: model.CircuitBreaker.FailureThreshold,
			SuccessThreshold: model.CircuitBreaker.SuccessThreshold,
			Timeout:          model.CircuitBreaker.Timeout,
			MaxTimeout:       model.CircuitBreaker.MaxTimeout,
		}
		
		p.circuitBreakers[model.Name] = NewCircuitBreaker(cbConfig)
		p.logger.WithFields(logrus.Fields{
			"model":             model.Name,
			"provider":          model.Provider,
			"failure_threshold": model.CircuitBreaker.FailureThreshold,
			"timeout":           model.CircuitBreaker.Timeout,
		}).Info("Circuit breaker initialized for model")
	}
}

// logModelStatus logs the status of all models
func (p *FallbackPipeline) logModelStatus() {
	enabledModels := p.modelRegistry.GetEnabledModels()
	
	p.logger.WithField("enabled_models", len(enabledModels)).Info("Model registry status")
	for _, model := range enabledModels {
		p.logger.WithFields(logrus.Fields{
			"model":            model.Name,
			"provider":         model.Provider,
			"priority":         model.Priority,
			"expected_latency": model.ExpectedLatency,
			"accuracy_score":   model.AccuracyScore,
		}).Info("Model available for fallback")
	}
}

// Analyze processes a detection request with intelligent fallback
func (p *FallbackPipeline) Analyze(ctx context.Context, req *DetectionRequest) (*DetectionResponse, error) {
	startTime := time.Now()

	// Validate input
	if len(req.Text) == 0 {
		return p.handleEmptyInput(startTime), nil
	}

	// Apply request-specific configuration
	config := p.applyConfig(req.Config)

	// Try models in priority order with circuit breaker protection
	enabledModels := p.modelRegistry.GetEnabledModels()
	
	var lastError error
	var attemptedModels []string

	for _, model := range enabledModels {
		circuitBreaker := p.circuitBreakers[model.Name]
		attemptedModels = append(attemptedModels, model.Name)
		
		p.logger.WithFields(logrus.Fields{
			"model": model.Name,
			"state": circuitBreaker.GetStateName(),
		}).Debug("Attempting model detection")

		// Try this model through circuit breaker
		var result *DetectionResult
		err := circuitBreaker.Call(func() error {
			var detectionErr error
			result, detectionErr = p.detectWithModel(model, req.Text)
			return detectionErr
		})

		if err == ErrCircuitOpen {
			p.logger.WithField("model", model.Name).Warn("Model circuit breaker is open, trying next model")
			lastError = err
			continue
		}

		if err != nil {
			p.logger.WithFields(logrus.Fields{
				"model": model.Name,
				"error": err.Error(),
			}).Warn("Model detection failed, trying next model")
			lastError = err
			continue
		}

		// Success! Build and return response
		response := p.buildResponse(result, config, time.Since(startTime), model.Name)
		p.metrics.RecordSuccess(time.Since(startTime), response)
		
		// Record Prometheus metrics
		resultType := "benign"
		if response.IsMalicious {
			resultType = "malicious"
		}
		p.metricsCollector.RecordDetectionRequest(
			model.Name, 
			resultType, 
			response.ThreatTypes, 
			time.Since(startTime),
		)
		
		p.logger.WithFields(logrus.Fields{
			"model":       model.Name,
			"confidence":  result.Score,
			"is_malicious": response.IsMalicious,
			"duration_ms": response.ProcessingTimeMs,
		}).Info("Detection completed successfully")

		return response, nil
	}

	// All models failed - record failure and return service unavailable error
	p.metrics.RecordFailure(time.Since(startTime))
	
	p.logger.WithFields(logrus.Fields{
		"attempted_models": attemptedModels,
		"last_error":       lastError.Error(),
		"duration_ms":      time.Since(startTime).Milliseconds(),
	}).Error("All detection models failed")

	return p.handleAllModelsFailed(startTime, attemptedModels), ErrAllModelsFailed
}

// detectWithModel performs detection using a specific model
func (p *FallbackPipeline) detectWithModel(model ModelConfig, text string) (*DetectionResult, error) {
	// For now, we'll use the existing LLMDetector but we can extend this
	// to support different model types (OpenAI, Anthropic, etc.) later
	
	// Create a temporary detector for this specific model
	// This is a simplified approach - in a full implementation, we'd have
	// specific handlers for each provider type
	
	switch model.Provider {
	case ProviderHuggingFace:
		return p.llmDetector.detectWithSpecificEndpoint(text, model)
	case ProviderGoogle:
		return p.llmDetector.detectWithSpecificEndpoint(text, model)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", model.Provider)
	}
}

// handleEmptyInput returns appropriate response for empty input
func (p *FallbackPipeline) handleEmptyInput(startTime time.Time) *DetectionResponse {
	return &DetectionResponse{
		IsMalicious:      false,
		Confidence:       0.0,
		ThreatTypes:      []string{},
		ProcessingTimeMs: time.Since(startTime).Milliseconds(),
		Reason:           "Empty input - not malicious",
		Endpoint:         "none",
	}
}

// handleAllModelsFailed returns response when all models are unavailable
func (p *FallbackPipeline) handleAllModelsFailed(startTime time.Time, attemptedModels []string) *DetectionResponse {
	return &DetectionResponse{
		IsMalicious:      false, // Conservative: assume safe when unsure
		Confidence:       0.5,   // Uncertain confidence
		ThreatTypes:      []string{},
		ProcessingTimeMs: time.Since(startTime).Milliseconds(),
		Reason:           fmt.Sprintf("All detection models unavailable (tried: %v) - returning safe classification", attemptedModels),
		Endpoint:         "fallback_failed",
	}
}

// buildResponse constructs the final detection response
func (p *FallbackPipeline) buildResponse(result *DetectionResult, config *DetectionConfig, duration time.Duration, modelUsed string) *DetectionResponse {
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

	return &DetectionResponse{
		IsMalicious:      isMalicious,
		Confidence:       result.Score,
		ThreatTypes:      threatTypes,
		ProcessingTimeMs: duration.Milliseconds(),
		Reason:           result.Reason,
		Endpoint:         modelUsed,
	}
}

// applyConfig applies request-specific configuration with defaults
func (p *FallbackPipeline) applyConfig(config *DetectionConfig) *DetectionConfig {
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
func (p *FallbackPipeline) GetMetrics() *Metrics {
	return p.metrics
}

// GetHealth returns pipeline health status with circuit breaker information
func (p *FallbackPipeline) GetHealth() *HealthStatus {
	enabledModels := p.modelRegistry.GetEnabledModels()
	modelStatuses := make(map[string]CircuitBreakerStats)
	
	healthyModels := 0
	for _, model := range enabledModels {
		if cb, exists := p.circuitBreakers[model.Name]; exists {
			stats := cb.GetStats()
			modelStatuses[model.Name] = stats
			if !stats.IsOpen {
				healthyModels++
			}
		}
	}

	// Determine overall status
	status := "healthy"
	if healthyModels == 0 {
		status = "critical - all models unavailable"
	} else if healthyModels < len(enabledModels) {
		status = "degraded - some models unavailable"
	}

	return &HealthStatus{
		Status:           status,
		Version:          "3.0.0-circuit-breaker-fallback",
		Uptime:           time.Since(p.startTime),
		RequestsServed:   p.metrics.GetRequestsTotal(),
		AverageLatency:   p.metrics.GetAverageLatency(),
		ModelsAvailable:  healthyModels,
		TotalModels:      len(enabledModels),
		CircuitBreakers:  modelStatuses,
		APIKeyConfigured: p.llmDetector.IsAvailable(),
	}
}

// GetCircuitBreakerStats returns statistics for all circuit breakers
func (p *FallbackPipeline) GetCircuitBreakerStats() map[string]CircuitBreakerStats {
	stats := make(map[string]CircuitBreakerStats)
	
	for name, cb := range p.circuitBreakers {
		stats[name] = cb.GetStats()
	}
	
	return stats
}

// ResetCircuitBreaker manually resets a specific circuit breaker
func (p *FallbackPipeline) ResetCircuitBreaker(modelName string) error {
	if cb, exists := p.circuitBreakers[modelName]; exists {
		cb.Reset()
		p.logger.WithField("model", modelName).Info("Circuit breaker manually reset")
		return nil
	}
	return fmt.Errorf("circuit breaker for model %s not found", modelName)
}