// Package internetbs implements a DNS provider for solving the DNS-01 challenge using internet.bs.
package internetbs

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"legotoolbox/providers/dns/internetbs/internal"
)

// Environment variables names.
const (
	envNamespace = "INTERNET_BS_"

	EnvAPIKey   = envNamespace + "API_KEY"
	EnvPassword = envNamespace + "PASSWORD"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	APIKey             string        `yaml:"apiKey"`
	Password           string        `yaml:"password"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	TTL                int           `yaml:"ttl"`
	HTTPClient         *http.Client  `yaml:"-"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt(EnvTTL, 3600),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, dns01.DefaultPropagationTimeout),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, dns01.DefaultPollingInterval),
		HTTPClient: &http.Client{
			Timeout: env.GetOrDefaultSecond(EnvHTTPTimeout, 30*time.Second),
		},
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		TTL:                3600,
		PropagationTimeout: dns01.DefaultPropagationTimeout,
		PollingInterval:    dns01.DefaultPollingInterval,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func GetYamlTemple() string {
	return `# API 密钥，用于身份验证
apiKey: "your-api-key-here"
# 密码，用于身份验证
password: "your-password-here"
# 传播超时时间，以秒为单位，表示等待 API 响应的最长时间
propagationTimeout: 30s
# 轮询间隔时间，以秒为单位，表示在轮询 API 时的时间间隔
pollingInterval: 10s
# TTL（存活时间），用于指定资源的存活时间
ttl: 3600`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *internal.Client
}

// NewDNSProvider returns a DNSProvider instance configured for internet.bs.
// Credentials must be passed in the environment variables: INTERNET_BS_API_KEY, INTERNET_BS_PASSWORD.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvAPIKey, EnvPassword)
	if err != nil {
		return nil, fmt.Errorf("internetbs: %w", err)
	}

	config := NewDefaultConfig()
	config.APIKey = values[EnvAPIKey]
	config.Password = values[EnvPassword]

	return NewDNSProviderConfig(config)
}

// ParseConfig parse bytes to config
func ParseConfig(rawConfig []byte) (*Config, error) {
	config := DefaultConfig()
	err := yaml.Unmarshal(rawConfig, &config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

// NewDNSProviderConfig return a DNSProvider instance configured for internet.bs.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("internetbs: the configuration of the DNS provider is nil")
	}

	if config.APIKey == "" || config.Password == "" {
		return nil, errors.New("internetbs: missing credentials")
	}

	client := internal.NewClient(config.APIKey, config.Password)

	if config.HTTPClient != nil {
		client.HTTPClient = config.HTTPClient
	}

	return &DNSProvider{
		config: config,
		client: client,
	}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// Present creates a TXT record using the specified parameters.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	query := internal.RecordQuery{
		FullRecordName: dns01.UnFqdn(info.EffectiveFQDN),
		Type:           "TXT",
		Value:          info.Value,
		TTL:            d.config.TTL,
	}

	err := d.client.AddRecord(context.Background(), query)
	if err != nil {
		return fmt.Errorf("internetbs: %w", err)
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	query := internal.RecordQuery{
		FullRecordName: dns01.UnFqdn(info.EffectiveFQDN),
		Type:           "TXT",
		Value:          info.Value,
		TTL:            d.config.TTL,
	}

	err := d.client.RemoveRecord(context.Background(), query)
	if err != nil {
		return fmt.Errorf("internetbs: %w", err)
	}

	return nil
}
