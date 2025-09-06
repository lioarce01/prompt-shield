package detector

import (
	"sync"
	"time"
	
	"prompt-injection-detection/internal/metrics"
)

// CircuitState represents the state of a circuit breaker
type CircuitState int

const (
	CircuitClosed   CircuitState = iota // Normal operation
	CircuitOpen                         // Blocking requests, using fallback
	CircuitHalfOpen                     // Testing if service recovered
)

// CircuitBreaker implements the circuit breaker pattern for AI model endpoints
type CircuitBreaker struct {
	name                string
	failureThreshold    int           // Number of failures to open circuit
	successThreshold    int           // Number of successes to close circuit from half-open
	timeout             time.Duration // Time to wait before trying half-open
	maxTimeout          time.Duration // Maximum timeout between attempts
	consecutiveFailures int
	consecutiveSuccesses int
	lastFailureTime     time.Time
	state               CircuitState
	mutex               sync.RWMutex
	totalRequests       int64
	successfulRequests  int64
	failedRequests      int64
	metricsCollector    *metrics.MetricsCollector
}

// CircuitBreakerConfig holds configuration for circuit breaker
type CircuitBreakerConfig struct {
	Name             string
	FailureThreshold int
	SuccessThreshold int
	Timeout          time.Duration
	MaxTimeout       time.Duration
}

// NewCircuitBreaker creates a new circuit breaker with the given configuration
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		name:             config.Name,
		failureThreshold: config.FailureThreshold,
		successThreshold: config.SuccessThreshold,
		timeout:          config.Timeout,
		maxTimeout:       config.MaxTimeout,
		state:            CircuitClosed,
	}
}

// Call executes a function through the circuit breaker
func (cb *CircuitBreaker) Call(fn func() error) error {
	if !cb.allowRequest() {
		return ErrCircuitOpen
	}

	cb.incrementTotalRequests()
	err := fn()
	cb.recordResult(err == nil)
	return err
}

// allowRequest determines if a request should be allowed through
func (cb *CircuitBreaker) allowRequest() bool {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	now := time.Now()

	switch cb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		// Check if timeout has passed to try half-open
		if now.Sub(cb.lastFailureTime) > cb.timeout {
			cb.state = CircuitHalfOpen
			cb.consecutiveSuccesses = 0
			return true
		}
		return false
	case CircuitHalfOpen:
		return true
	default:
		return false
	}
}

// recordResult records the result of a request and updates circuit state
func (cb *CircuitBreaker) recordResult(success bool) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	if success {
		cb.consecutiveFailures = 0
		cb.consecutiveSuccesses++
		cb.successfulRequests++

		// If in half-open state and got enough successes, close circuit
		if cb.state == CircuitHalfOpen && cb.consecutiveSuccesses >= cb.successThreshold {
			cb.state = CircuitClosed
			cb.consecutiveSuccesses = 0
		}
	} else {
		cb.consecutiveSuccesses = 0
		cb.consecutiveFailures++
		cb.failedRequests++
		cb.lastFailureTime = time.Now()

		// If failures exceed threshold, open circuit
		if cb.consecutiveFailures >= cb.failureThreshold {
			cb.state = CircuitOpen
			// Exponential backoff for timeout, but cap at maxTimeout
			newTimeout := cb.timeout * time.Duration(cb.consecutiveFailures)
			if newTimeout > cb.maxTimeout {
				newTimeout = cb.maxTimeout
			}
			cb.timeout = newTimeout
		}
	}
}

// incrementTotalRequests safely increments the total request counter
func (cb *CircuitBreaker) incrementTotalRequests() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	cb.totalRequests++
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state
}

// GetStateName returns the human-readable name of the current state
func (cb *CircuitBreaker) GetStateName() string {
	state := cb.GetState()
	switch state {
	case CircuitClosed:
		return "CLOSED"
	case CircuitOpen:
		return "OPEN"
	case CircuitHalfOpen:
		return "HALF_OPEN"
	default:
		return "UNKNOWN"
	}
}

// GetStats returns statistics about the circuit breaker
func (cb *CircuitBreaker) GetStats() CircuitBreakerStats {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	var successRate float64
	if cb.totalRequests > 0 {
		successRate = float64(cb.successfulRequests) / float64(cb.totalRequests)
	}

	return CircuitBreakerStats{
		Name:                 cb.name,
		State:                cb.GetStateName(),
		ConsecutiveFailures:  cb.consecutiveFailures,
		ConsecutiveSuccesses: cb.consecutiveSuccesses,
		LastFailureTime:      cb.lastFailureTime,
		Timeout:              cb.timeout,
		TotalRequests:        cb.totalRequests,
		SuccessfulRequests:   cb.successfulRequests,
		FailedRequests:       cb.failedRequests,
		SuccessRate:          successRate,
		IsOpen:               cb.state == CircuitOpen,
	}
}

// CircuitBreakerStats holds statistics for a circuit breaker
type CircuitBreakerStats struct {
	Name                 string        `json:"name"`
	State                string        `json:"state"`
	ConsecutiveFailures  int           `json:"consecutive_failures"`
	ConsecutiveSuccesses int           `json:"consecutive_successes"`
	LastFailureTime      time.Time     `json:"last_failure_time,omitempty"`
	Timeout              time.Duration `json:"timeout_duration"`
	TotalRequests        int64         `json:"total_requests"`
	SuccessfulRequests   int64         `json:"successful_requests"`
	FailedRequests       int64         `json:"failed_requests"`
	SuccessRate          float64       `json:"success_rate"`
	IsOpen               bool          `json:"is_open"`
}

// Reset manually resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.state = CircuitClosed
	cb.consecutiveFailures = 0
	cb.consecutiveSuccesses = 0
	// Reset timeout to original value would need to be stored separately
	// For now, keep current timeout
}

// Custom errors for circuit breaker
var (
	ErrCircuitOpen    = &CircuitBreakerError{Message: "circuit breaker is open"}
	ErrAllModelsFailed = &CircuitBreakerError{Message: "all detection models are currently unavailable"}
)

// CircuitBreakerError represents an error from the circuit breaker
type CircuitBreakerError struct {
	Message string
}

func (e *CircuitBreakerError) Error() string {
	return e.Message
}