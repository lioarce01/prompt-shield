package detector

import (
	"fmt"
	"time"
)

// ModelType represents different types of AI models
type ModelType string

const (
	ModelTypeClassification ModelType = "classification" // HuggingFace classification models
	ModelTypeGenAI          ModelType = "genai"          // Generative AI models (GPT, Gemini, etc.)
)

// ModelProvider represents different AI service providers
type ModelProvider string

const (
	ProviderHuggingFace ModelProvider = "huggingface"
	ProviderOpenAI      ModelProvider = "openai"
	ProviderGoogle      ModelProvider = "google"
	ProviderAnthropic   ModelProvider = "anthropic"
	ProviderGrok        ModelProvider = "grok"
)

// ModelConfig defines configuration for any AI model
type ModelConfig struct {
	Name             string        `json:"name"`              // Human-readable name
	Provider         ModelProvider `json:"provider"`          // Service provider
	Type             ModelType     `json:"type"`              // Model type
	Model            string        `json:"model"`             // Model identifier
	URL              string        `json:"url,omitempty"`     // API endpoint
	APIKeyEnvVar     string        `json:"api_key_env"`       // Environment variable for API key
	Timeout          time.Duration `json:"timeout"`           // Request timeout
	Priority         int           `json:"priority"`          // Fallback priority (1=highest)
	CostPerRequest   float64       `json:"cost_per_request"`  // Cost in USD per request
	ExpectedLatency  time.Duration `json:"expected_latency"`  // Expected response time
	AccuracyScore    float64       `json:"accuracy_score"`    // Model accuracy (0-1)
	Enabled          bool          `json:"enabled"`           // Whether model is active
	CircuitBreaker   CBConfig      `json:"circuit_breaker"`   // Circuit breaker config
}

// CBConfig holds circuit breaker configuration for a model
type CBConfig struct {
	FailureThreshold int           `json:"failure_threshold"`
	SuccessThreshold int           `json:"success_threshold"`  
	Timeout          time.Duration `json:"timeout"`
	MaxTimeout       time.Duration `json:"max_timeout"`
}

// ModelRegistry manages available AI models and their configurations
type ModelRegistry struct {
	models        []ModelConfig
	enabledModels []ModelConfig
}

// NewModelRegistry creates a new model registry with startup-friendly configurations
func NewModelRegistry() *ModelRegistry {
	registry := &ModelRegistry{
		models: getStartupModelConfigs(),
	}
	registry.refreshEnabledModels()
	return registry
}

// LoadFromConfig loads model configurations from external source
func (r *ModelRegistry) LoadFromConfig(configs []ModelConfig) {
	r.models = configs
	r.refreshEnabledModels()
}

// GetEnabledModels returns models sorted by priority (1=highest priority)
func (r *ModelRegistry) GetEnabledModels() []ModelConfig {
	return r.enabledModels
}

// GetModelByName returns model configuration by name
func (r *ModelRegistry) GetModelByName(name string) (ModelConfig, error) {
	for _, model := range r.models {
		if model.Name == name {
			return model, nil
		}
	}
	return ModelConfig{}, fmt.Errorf("model %s not found", name)
}

// GetAllModels returns all model configurations (enabled and disabled)
func (r *ModelRegistry) GetAllModels() []ModelConfig {
	return r.models
}

// EnableModel enables a model by name
func (r *ModelRegistry) EnableModel(name string) error {
	for i := range r.models {
		if r.models[i].Name == name {
			r.models[i].Enabled = true
			r.refreshEnabledModels()
			return nil
		}
	}
	return fmt.Errorf("model %s not found", name)
}

// DisableModel disables a model by name  
func (r *ModelRegistry) DisableModel(name string) error {
	for i := range r.models {
		if r.models[i].Name == name {
			r.models[i].Enabled = false
			r.refreshEnabledModels()
			return nil
		}
	}
	return fmt.Errorf("model %s not found", name)
}

// UpdateModelPriority changes the priority of a model
func (r *ModelRegistry) UpdateModelPriority(name string, newPriority int) error {
	for i := range r.models {
		if r.models[i].Name == name {
			r.models[i].Priority = newPriority
			r.refreshEnabledModels()
			return nil
		}
	}
	return fmt.Errorf("model %s not found", name)
}

// refreshEnabledModels updates the enabled models list and sorts by priority
func (r *ModelRegistry) refreshEnabledModels() {
	r.enabledModels = make([]ModelConfig, 0)
	
	for _, model := range r.models {
		if model.Enabled {
			r.enabledModels = append(r.enabledModels, model)
		}
	}
	
	// Sort by priority (1 = highest, 3 = lowest)
	for i := 0; i < len(r.enabledModels); i++ {
		for j := i + 1; j < len(r.enabledModels); j++ {
			if r.enabledModels[i].Priority > r.enabledModels[j].Priority {
				r.enabledModels[i], r.enabledModels[j] = r.enabledModels[j], r.enabledModels[i]
			}
		}
	}
}

// getStartupModelConfigs returns startup-friendly model configurations (free models only)
func getStartupModelConfigs() []ModelConfig {
	return []ModelConfig{
		// Startup Models - All Free
		{
			Name:            "ProtectAI-DeBERTa-v3",
			Provider:        ProviderHuggingFace,
			Type:            ModelTypeClassification,
			Model:           "protectai/deberta-v3-base-prompt-injection-v2",
			URL:             "https://api-inference.huggingface.co/models/protectai/deberta-v3-base-prompt-injection-v2",
			APIKeyEnvVar:    "HUGGINGFACE_API_KEY",
			Timeout:         15 * time.Second,
			Priority:        1, // Fastest, specialized for prompt injection
			CostPerRequest:  0.0, // Free
			ExpectedLatency: 2 * time.Second,
			AccuracyScore:   0.92,
			Enabled:         true,
			CircuitBreaker: CBConfig{
				FailureThreshold: 5,  // Allow 5 failures before opening
				SuccessThreshold: 3,  // Need 3 successes to close
				Timeout:          30 * time.Second,
				MaxTimeout:       5 * time.Minute,
			},
		},
		{
			Name:            "Meta-Llama-Prompt-Guard",
			Provider:        ProviderHuggingFace,
			Type:            ModelTypeClassification,
			Model:           "meta-llama/Llama-Prompt-Guard-2-86M",
			URL:             "https://router.huggingface.co/hf-inference/models/meta-llama/Llama-Prompt-Guard-2-86M",
			APIKeyEnvVar:    "HUGGINGFACE_API_KEY",
			Timeout:         15 * time.Second,
			Priority:        2, // Fast and reliable fallback
			CostPerRequest:  0.0, // Free
			ExpectedLatency: 3 * time.Second,
			AccuracyScore:   0.89,
			Enabled:         true,
			CircuitBreaker: CBConfig{
				FailureThreshold: 5,
				SuccessThreshold: 3,
				Timeout:          30 * time.Second,
				MaxTimeout:       5 * time.Minute,
			},
		},
		{
			Name:            "Gemini-2.0-Flash",
			Provider:        ProviderGoogle,
			Type:            ModelTypeGenAI,
			Model:           "gemini-2.0-flash",
			URL:             "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
			APIKeyEnvVar:    "GEMINI_API_KEY",
			Timeout:         15 * time.Second,
			Priority:        3, // Slower but smartest, different provider
			CostPerRequest:  0.0, // Free tier
			ExpectedLatency: 5 * time.Second,
			AccuracyScore:   0.95,
			Enabled:         true,
			CircuitBreaker: CBConfig{
				FailureThreshold: 3,  // More sensitive for GenAI
				SuccessThreshold: 2,  
				Timeout:          60 * time.Second, // Longer timeout for GenAI
				MaxTimeout:       10 * time.Minute,
			},
		},
		
		// Future Premium Models - Disabled by default, enable when you have budget
		{
			Name:            "GPT-4o-Mini",
			Provider:        ProviderOpenAI,
			Type:            ModelTypeGenAI,
			Model:           "gpt-4o-mini",
			URL:             "https://api.openai.com/v1/chat/completions",
			APIKeyEnvVar:    "OPENAI_API_KEY",
			Timeout:         20 * time.Second,
			Priority:        1, // Would be primary when enabled
			CostPerRequest:  0.00015, // $0.15 per 1K tokens
			ExpectedLatency: 3 * time.Second,
			AccuracyScore:   0.94,
			Enabled:         false, // Disabled until you have budget
			CircuitBreaker: CBConfig{
				FailureThreshold: 3,
				SuccessThreshold: 2,
				Timeout:          45 * time.Second,
				MaxTimeout:       8 * time.Minute,
			},
		},
		{
			Name:            "GPT-4o",
			Provider:        ProviderOpenAI,
			Type:            ModelTypeGenAI,
			Model:           "gpt-4o",
			URL:             "https://api.openai.com/v1/chat/completions",
			APIKeyEnvVar:    "OPENAI_API_KEY",
			Timeout:         30 * time.Second,
			Priority:        2, 
			CostPerRequest:  0.0025, // $2.50 per 1K tokens
			ExpectedLatency: 8 * time.Second,
			AccuracyScore:   0.97,
			Enabled:         false, // Disabled until you have budget
			CircuitBreaker: CBConfig{
				FailureThreshold: 3,
				SuccessThreshold: 2,
				Timeout:          60 * time.Second,
				MaxTimeout:       10 * time.Minute,
			},
		},
		{
			Name:            "Claude-3.5-Sonnet",
			Provider:        ProviderAnthropic,
			Type:            ModelTypeGenAI,
			Model:           "claude-3-5-sonnet-20241022",
			URL:             "https://api.anthropic.com/v1/messages",
			APIKeyEnvVar:    "ANTHROPIC_API_KEY",
			Timeout:         25 * time.Second,
			Priority:        3,
			CostPerRequest:  0.003, // $3.00 per 1K tokens
			ExpectedLatency: 6 * time.Second,
			AccuracyScore:   0.96,
			Enabled:         false, // Disabled until you have budget
			CircuitBreaker: CBConfig{
				FailureThreshold: 3,
				SuccessThreshold: 2,
				Timeout:          60 * time.Second,
				MaxTimeout:       10 * time.Minute,
			},
		},
	}
}