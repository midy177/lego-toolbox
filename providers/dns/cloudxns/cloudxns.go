// Package cloudxns implements a DNS provider for solving the DNS-01 challenge using CloudXNS DNS.
package cloudxns

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"lego-toolbox/providers/dns/cloudxns/internal"
)

// Environment variables names.
const (
	envNamespace = "CLOUDXNS_"

	EnvAPIKey    = envNamespace + "API_KEY"
	EnvSecretKey = envNamespace + "SECRET_KEY"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	ApiKey             string        `yaml:"apiKey"`
	SecretKey          string        `yaml:"secretKey"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	TTL                int           `yaml:"ttl"`
	HTTPClient         *http.Client  `yaml:"-"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, dns01.DefaultPropagationTimeout),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, dns01.DefaultPollingInterval),
		TTL:                env.GetOrDefaultInt(EnvTTL, dns01.DefaultTTL),
		HTTPClient: &http.Client{
			Timeout: env.GetOrDefaultSecond(EnvHTTPTimeout, 30*time.Second),
		},
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		PropagationTimeout: dns01.DefaultPropagationTimeout,
		PollingInterval:    dns01.DefaultPollingInterval,
		TTL:                dns01.DefaultTTL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *internal.Client
}

// NewDNSProvider returns a DNSProvider instance configured for CloudXNS.
// Credentials must be passed in the environment variables:
// CLOUDXNS_API_KEY and CLOUDXNS_SECRET_KEY.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvAPIKey, EnvSecretKey)
	if err != nil {
		return nil, fmt.Errorf("cloudxns: %w", err)
	}

	config := NewDefaultConfig()
	config.ApiKey = values[EnvAPIKey]
	config.SecretKey = values[EnvSecretKey]

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

// NewDNSProviderConfig return a DNSProvider instance configured for CloudXNS.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("cloudxns: the configuration of the DNS provider is nil")
	}

	client, err := internal.NewClient(config.ApiKey, config.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("cloudxns: %w", err)
	}

	if config.HTTPClient != nil {
		client.HTTPClient = config.HTTPClient
	}

	return &DNSProvider{client: client, config: config}, nil
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	challengeInfo := dns01.GetChallengeInfo(domain, keyAuth)

	ctx := context.Background()

	info, err := d.client.GetDomainInformation(ctx, challengeInfo.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("cloudxns: %w", err)
	}

	err = d.client.AddTxtRecord(ctx, info, challengeInfo.EffectiveFQDN, challengeInfo.Value, d.config.TTL)
	if err != nil {
		return fmt.Errorf("cloudxns: %w", err)
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	challengeInfo := dns01.GetChallengeInfo(domain, keyAuth)

	ctx := context.Background()

	info, err := d.client.GetDomainInformation(ctx, challengeInfo.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("cloudxns: %w", err)
	}

	record, err := d.client.FindTxtRecord(ctx, info.ID, challengeInfo.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("cloudxns: %w", err)
	}

	err = d.client.RemoveTxtRecord(ctx, record.RecordID, info.ID)
	if err != nil {
		return fmt.Errorf("cloudxns: %w", err)
	}

	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}
