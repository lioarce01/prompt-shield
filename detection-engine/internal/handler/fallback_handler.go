package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"prompt-injection-detection/internal/detector"
)

// FallbackDetectionHandler handles HTTP requests for prompt injection detection with circuit breakers
type FallbackDetectionHandler struct {
	pipeline *detector.FallbackPipeline
	logger   *logrus.Logger
}

// NewFallbackDetectionHandler creates a new fallback detection handler
func NewFallbackDetectionHandler(pipeline *detector.FallbackPipeline, logger *logrus.Logger) *FallbackDetectionHandler {
	return &FallbackDetectionHandler{
		pipeline: pipeline,
		logger:   logger,
	}
}

// DetectInjection handles POST /v1/detect requests with circuit breaker fallback
func (h *FallbackDetectionHandler) DetectInjection(c *gin.Context) {
	var req detector.DetectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Error("Invalid request payload")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request payload",
			"details": err.Error(),
		})
		return
	}

	// Set timeout for detection
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Log request (be careful not to log sensitive content)
	h.logger.WithFields(logrus.Fields{
		"text_length": len(req.Text),
		"config":      req.Config,
		"client_ip":   c.ClientIP(),
	}).Info("Processing detection request with circuit breaker fallback")

	// Process detection
	response, err := h.pipeline.Analyze(ctx, &req)
	if err != nil {
		h.logger.WithError(err).Error("Detection analysis failed")

		// Check if all models failed (service unavailable)
		if err == detector.ErrAllModelsFailed {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":   "All detection models are temporarily unavailable",
				"details": "Please try again in a few minutes",
				"retry_after": 60, // Suggest retry after 60 seconds
			})
			return
		}

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

	// Log response with model used
	h.logger.WithFields(logrus.Fields{
		"is_malicious":       response.IsMalicious,
		"confidence":         response.Confidence,
		"threat_types":       response.ThreatTypes,
		"processing_time_ms": response.ProcessingTimeMs,
		"model_used":         response.Endpoint,
	}).Info("Detection completed")

	// Return response
	c.JSON(http.StatusOK, response)
}

// HealthCheck handles GET /health requests with circuit breaker status
func (h *FallbackDetectionHandler) HealthCheck(c *gin.Context) {
	health := h.pipeline.GetHealth()

	// Determine status code based on health
	statusCode := http.StatusOK
	if health.Status == "critical - all models unavailable" {
		statusCode = http.StatusServiceUnavailable
	} else if health.Status != "healthy" {
		statusCode = http.StatusPartialContent // 206 for degraded service
	}

	c.JSON(statusCode, health)
}

// GetMetrics handles GET /v1/metrics requests
func (h *FallbackDetectionHandler) GetMetrics(c *gin.Context) {
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
		"detection_method":     "circuit_breaker_fallback",
		"detections_by_threat": metrics.DetectionsByThreat,
	}

	c.JSON(http.StatusOK, response)
}

// GetCircuitBreakers handles GET /v1/circuit-breakers requests
func (h *FallbackDetectionHandler) GetCircuitBreakers(c *gin.Context) {
	stats := h.pipeline.GetCircuitBreakerStats()

	response := gin.H{
		"circuit_breakers": stats,
		"total_models":     len(stats),
		"timestamp":        time.Now().Unix(),
	}

	// Add summary information
	openCount := 0
	closedCount := 0
	halfOpenCount := 0

	for _, stat := range stats {
		switch stat.State {
		case "OPEN":
			openCount++
		case "CLOSED":
			closedCount++
		case "HALF_OPEN":
			halfOpenCount++
		}
	}

	response["summary"] = gin.H{
		"open":      openCount,
		"closed":    closedCount,
		"half_open": halfOpenCount,
		"healthy":   closedCount + halfOpenCount,
	}

	c.JSON(http.StatusOK, response)
}

// ResetCircuitBreaker handles POST /v1/circuit-breakers/:model/reset requests
func (h *FallbackDetectionHandler) ResetCircuitBreaker(c *gin.Context) {
	modelName := c.Param("model")
	if modelName == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Model name is required",
		})
		return
	}

	err := h.pipeline.ResetCircuitBreaker(modelName)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"model": modelName,
			"error": err.Error(),
		}).Error("Failed to reset circuit breaker")

		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Circuit breaker not found",
			"details": err.Error(),
		})
		return
	}

	h.logger.WithField("model", modelName).Info("Circuit breaker manually reset")

	c.JSON(http.StatusOK, gin.H{
		"message": "Circuit breaker reset successfully",
		"model":   modelName,
	})
}

// DiagnoseLLM handles GET /v1/diagnose-llm requests with model registry info
func (h *FallbackDetectionHandler) DiagnoseLLM(c *gin.Context) {
	// Get pipeline health including circuit breaker status
	health := h.pipeline.GetHealth()
	circuitBreakers := h.pipeline.GetCircuitBreakerStats()

	// Build model information from circuit breaker stats
	models := make([]gin.H, 0, len(circuitBreakers))
	for name, stats := range circuitBreakers {
		models = append(models, gin.H{
			"name":                 name,
			"state":                stats.State,
			"is_healthy":           !stats.IsOpen,
			"total_requests":       stats.TotalRequests,
			"success_rate":         stats.SuccessRate,
			"consecutive_failures": stats.ConsecutiveFailures,
			"last_failure":         stats.LastFailureTime,
		})
	}

	response := gin.H{
		"detection_method":       "circuit_breaker_fallback",
		"models_available":       health.ModelsAvailable,
		"total_models":           health.TotalModels,
		"api_key_configured":     health.APIKeyConfigured,
		"models":                 models,
		"circuit_breaker_stats":  circuitBreakers,
		"fallback_strategy":      "ProtectAI -> Moonshot-Kimi-K2 -> Gemini -> HTTP 503",
		"note":                   "Circuit breaker enabled with automatic fallback",
	}

	c.JSON(http.StatusOK, response)
}