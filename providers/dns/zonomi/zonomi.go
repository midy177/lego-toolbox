// Package zonomi implements a DNS provider for solving the DNS-01 challenge using Zonomi DNS.
package zonomi

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"legotoolbox/providers/dns/internal/rimuhosting"
)

// Environment variables names.
const (
	envNamespace = "ZONOMI_"

	EnvAPIKey = envNamespace + "API_KEY"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	APIKey             string        `yaml:"apiKey"`
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
	return `# config.yaml
apiKey: "your_api_key"                      # API 密钥
propagationTimeout: 60s                     # 传播超时时间，单位为秒
pollingInterval: 2s                         # 轮询间隔时间，单位为秒
ttl: 3600                                   # TTL 值`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *rimuhosting.Client
}

// NewDNSProvider returns a DNSProvider instance configured for Zonomi.
// Credentials must be passed in the environment variables.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvAPIKey)
	if err != nil {
		return nil, fmt.Errorf("zonomi: %w", err)
	}

	config := NewDefaultConfig()
	config.APIKey = values[EnvAPIKey]

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

// NewDNSProviderConfig return a DNSProvider instance configured for Zonomi.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("zonomi: the configuration of the DNS provider is nil")
	}

	if config.APIKey == "" {
		return nil, errors.New("zonomi: incomplete credentials, missing API key")
	}

	client := rimuhosting.NewClient(config.APIKey)
	client.BaseURL = rimuhosting.DefaultZonomiBaseURL

	if config.HTTPClient != nil {
		client.HTTPClient = config.HTTPClient
	}

	return &DNSProvider{config: config, client: client}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// Present creates a TXT record using the specified parameters.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	ctx := context.Background()

	records, err := d.client.FindTXTRecords(ctx, dns01.UnFqdn(info.EffectiveFQDN))
	if err != nil {
		return fmt.Errorf("zonomi: failed to find record(s) for %s: %w", domain, err)
	}

	actions := []rimuhosting.ActionParameter{
		rimuhosting.NewAddRecordAction(dns01.UnFqdn(info.EffectiveFQDN), info.Value, d.config.TTL),
	}

	for _, record := range records {
		actions = append(actions, rimuhosting.NewAddRecordAction(record.Name, record.Content, d.config.TTL))
	}

	_, err = d.client.DoActions(ctx, actions...)
	if err != nil {
		return fmt.Errorf("zonomi: failed to add record(s) for %s: %w", domain, err)
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	action := rimuhosting.NewDeleteRecordAction(dns01.UnFqdn(info.EffectiveFQDN), info.Value)

	_, err := d.client.DoActions(context.Background(), action)
	if err != nil {
		return fmt.Errorf("zonomi: failed to delete record for %s: %w", domain, err)
	}

	return nil
}
