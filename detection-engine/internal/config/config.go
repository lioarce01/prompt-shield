package config

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Detection DetectionConfig `mapstructure:"detection"`
	Patterns  PatternsConfig  `mapstructure:"patterns"`
	Metrics   MetricsConfig   `mapstructure:"metrics"`
}

type ServerConfig struct {
	Port    int           `mapstructure:"port"`
	Timeout time.Duration `mapstructure:"timeout"`
}

type DetectionConfig struct {
	ConfidenceThreshold float64 `mapstructure:"confidence_threshold"`
	MaxPromptLength     int     `mapstructure:"max_prompt_length"`
	WorkerPoolSize      int     `mapstructure:"worker_pool_size"`
}

type PatternsConfig struct {
	UpdateInterval time.Duration `mapstructure:"update_interval"`
	CacheSize      int           `mapstructure:"cache_size"`
}

type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"`
}

func Load() (*Config, error) {
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.timeout", "30s")
	viper.SetDefault("detection.confidence_threshold", 0.5) // Lowered from 0.7 to 0.5
	viper.SetDefault("detection.max_prompt_length", 10000)
	viper.SetDefault("detection.worker_pool_size", 10)
	viper.SetDefault("patterns.update_interval", "1h")
	viper.SetDefault("patterns.cache_size", 1000)
	viper.SetDefault("metrics.enabled", true)
	viper.SetDefault("metrics.path", "/metrics")

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath(".")

	viper.AutomaticEnv()

	// Read config file (optional, will use defaults if not found)
	_ = viper.ReadInConfig()

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}
