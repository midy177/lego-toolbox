// Package dode implements a DNS provider for solving the DNS-01 challenge using do.de.
package dode

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"legotoolbox/providers/dns/dode/internal"
)

// Environment variables names.
const (
	envNamespace = "DODE_"

	EnvToken = envNamespace + "TOKEN"

	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
	EnvSequenceInterval   = envNamespace + "SEQUENCE_INTERVAL"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	Token              string        `yaml:"token"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	SequenceInterval   time.Duration `yaml:"sequenceInterval"`
	HTTPClient         *http.Client  `yaml:"-"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, dns01.DefaultPropagationTimeout),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, dns01.DefaultPollingInterval),
		SequenceInterval:   env.GetOrDefaultSecond(EnvSequenceInterval, dns01.DefaultPropagationTimeout),
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
		SequenceInterval:   dns01.DefaultPropagationTimeout,
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

// NewDNSProvider returns a new DNS provider using
// environment variable DODE_TOKEN for adding and removing the DNS record.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvToken)
	if err != nil {
		return nil, fmt.Errorf("do.de: %w", err)
	}

	config := NewDefaultConfig()
	config.Token = values[EnvToken]

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

// NewDNSProviderConfig return a DNSProvider instance configured for do.de.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("do.de: the configuration of the DNS provider is nil")
	}

	if config.Token == "" {
		return nil, errors.New("do.de: credentials missing")
	}

	client := internal.NewClient(config.Token)

	if config.HTTPClient != nil {
		client.HTTPClient = config.HTTPClient
	}

	return &DNSProvider{config: config, client: client}, nil
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return d.client.UpdateTxtRecord(context.Background(), info.EffectiveFQDN, info.Value, false)
}

// CleanUp clears TXT record.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return d.client.UpdateTxtRecord(context.Background(), info.EffectiveFQDN, "", true)
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// Sequential All DNS challenges for this provider will be resolved sequentially.
// Returns the interval between each iteration.
func (d *DNSProvider) Sequential() time.Duration {
	return d.config.SequenceInterval
}
