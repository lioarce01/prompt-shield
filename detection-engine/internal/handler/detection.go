package handler

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"prompt-injection-detection/internal/detector"
)

// DetectionHandler handles HTTP requests for prompt injection detection
type DetectionHandler struct {
	pipeline *detector.Pipeline
	logger   *logrus.Logger
}

// NewDetectionHandler creates a new detection handler
func NewDetectionHandler(pipeline *detector.Pipeline, logger *logrus.Logger) *DetectionHandler {
	return &DetectionHandler{
		pipeline: pipeline,
		logger:   logger,
	}
}

// DetectInjection handles POST /v1/detect requests
func (h *DetectionHandler) DetectInjection(c *gin.Context) {
	var req detector.DetectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Error("Invalid request payload")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request payload",
			"details": err.Error(),
		})
		return
	}

	// Remove validation - let pipeline handle empty text gracefully

	// Set timeout for detection
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Log request (be careful not to log sensitive content)
	h.logger.WithFields(logrus.Fields{
		"text_length": len(req.Text),
		"config":      req.Config,
		"client_ip":   c.ClientIP(),
	}).Info("Processing detection request")

	// Process detection
	response, err := h.pipeline.Analyze(ctx, &req)
	if err != nil {
		h.logger.WithError(err).Error("Detection analysis failed")

		// Determine appropriate HTTP status code
		statusCode := http.StatusInternalServerError
		if ctx.Err() == context.DeadlineExceeded {
			statusCode = http.StatusRequestTimeout
		}

		c.JSON(statusCode, gin.H{
			"error":   "Detection analysis failed",
			"details": err.Error(),
		})
		return
	}

	// Log response
	h.logger.WithFields(logrus.Fields{
		"is_malicious":       response.IsMalicious,
		"confidence":         response.Confidence,
		"threat_types":       response.ThreatTypes,
		"processing_time_ms": response.ProcessingTimeMs,
	}).Info("Detection completed")

	// Return response
	c.JSON(http.StatusOK, response)
}

// DiagnoseLLM handles GET /v1/diagnose-llm requests
func (h *DetectionHandler) DiagnoseLLM(c *gin.Context) {
	// Get pipeline health including LLM status
	health := h.pipeline.GetHealth()

	// Test LLM endpoints specifically
	llmDiagnostic := h.pipeline.DiagnoseLLMEndpoints()

	// Build current cloud endpoints from actual configuration
	cloudEndpoints := make(map[string]interface{})
	for i, endpoint := range health.LLMEndpoints {
		key := fmt.Sprintf("endpoint_%d", i)
		// Use the actual URL from the diagnostic rather than constructing it
		endpointKey := fmt.Sprintf("endpoint_%d", i)
		if endpointData, exists := llmDiagnostic[endpointKey]; exists {
			if endpointMap, ok := endpointData.(map[string]interface{}); ok {
				if url, exists := endpointMap["url"]; exists {
					cloudEndpoints[key] = url
					continue
				}
			}
		}
		// Fallback to model name if URL extraction fails
		cloudEndpoints[key] = endpoint
	}

	response := gin.H{
		"llm_enabled":              health.LLMEndpoints,
		"llm_diagnostic":           llmDiagnostic,
		"api_key_configured":       health.APIKeyConfigured,
		"classification_threshold": 0.6,
		"cloud_endpoints":          cloudEndpoints,
		"note":                     "LLM-only detection with specialized prompt injection models",
	}

	c.JSON(http.StatusOK, response)
}

// HealthCheck handles GET /health requests
func (h *DetectionHandler) HealthCheck(c *gin.Context) {
	health := h.pipeline.GetHealth()

	// Determine status code based on health
	statusCode := http.StatusOK
	if health.Status != "healthy" {
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, health)
}

// GetMetrics handles GET /v1/metrics requests
func (h *DetectionHandler) GetMetrics(c *gin.Context) {
	metrics := h.pipeline.GetMetrics()

	// Convert metrics to response format
	successRate := float64(0)
	if metrics.RequestsTotal > 0 {
		successRate = float64(metrics.RequestsSuccessful) / float64(metrics.RequestsTotal)
	}

	response := gin.H{
		"requests_total":       metrics.GetRequestsTotal(),
		"requests_successful":  metrics.RequestsSuccessful,
		"requests_failed":      metrics.RequestsFailed,
		"success_rate":         successRate,
		"average_latency_ms":   metrics.GetAverageLatency().Milliseconds(),
		"detection_method":     "llm_only",
		"detections_by_threat": metrics.DetectionsByThreat,
	}

	c.JSON(http.StatusOK, response)
}

// DetectBatch handles bulk detection requests (future enhancement)
func (h *DetectionHandler) DetectBatch(c *gin.Context) {
	var req struct {
		Texts  []string                  `json:"texts" binding:"required"`
		Config *detector.DetectionConfig `json:"config,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request payload",
			"details": err.Error(),
		})
		return
	}

	// Validate batch size
	if len(req.Texts) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "At least one text is required",
		})
		return
	}

	if len(req.Texts) > 100 { // Limit batch size
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Batch size cannot exceed 100 texts",
		})
		return
	}

	// Process each text
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	responses := make([]*detector.DetectionResponse, len(req.Texts))
	errors := make([]string, len(req.Texts))

	for i, text := range req.Texts {
		detectionReq := detector.DetectionRequest{
			Text:   text,
			Config: req.Config,
		}

		response, err := h.pipeline.Analyze(ctx, &detectionReq)
		if err != nil {
			errors[i] = err.Error()
		} else {
			responses[i] = response
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"results": responses,
		"errors":  errors,
	})
}
