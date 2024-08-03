// Package autodns implements a DNS provider for solving the DNS-01 challenge using auto DNS.
package autodns

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"net/url"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"lego-toolbox/providers/dns/autodns/internal"
)

// Environment variables names.
const (
	envNamespace = "AUTODNS_"

	EnvAPIUser            = envNamespace + "API_USER"
	EnvAPIPassword        = envNamespace + "API_PASSWORD"
	EnvAPIEndpoint        = envNamespace + "ENDPOINT"
	EnvAPIEndpointContext = envNamespace + "CONTEXT"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	Endpoint           *url.URL      `yaml:"-"`
	Username           string        `yaml:"username"`
	Password           string        `yaml:"password"`
	Context            int           `yaml:"context"`
	TTL                int           `yaml:"ttl"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	HTTPClient         *http.Client  `yaml:"-"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	endpoint, _ := url.Parse(env.GetOrDefaultString(EnvAPIEndpoint, internal.DefaultEndpoint))

	return &Config{
		Endpoint:           endpoint,
		Context:            env.GetOrDefaultInt(EnvAPIEndpointContext, internal.DefaultEndpointContext),
		TTL:                env.GetOrDefaultInt(EnvTTL, 600),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, 2*time.Minute),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, 2*time.Second),
		HTTPClient: &http.Client{
			Timeout: env.GetOrDefaultSecond(EnvHTTPTimeout, 30*time.Second),
		},
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	endpoint, _ := url.Parse(internal.DefaultEndpoint)

	return &Config{
		Endpoint:           endpoint,
		Context:            internal.DefaultEndpointContext,
		TTL:                600,
		PropagationTimeout: 2 * time.Minute,
		PollingInterval:    2 * time.Second,
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

// NewDNSProvider returns a DNSProvider instance configured for autoDNS.
// Credentials must be passed in the environment variables.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvAPIUser, EnvAPIPassword)
	if err != nil {
		return nil, fmt.Errorf("autodns: %w", err)
	}

	config := NewDefaultConfig()
	config.Username = values[EnvAPIUser]
	config.Password = values[EnvAPIPassword]

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

// NewDNSProviderConfig return a DNSProvider instance configured for autoDNS.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("autodns: config is nil")
	}

	if config.Username == "" {
		return nil, errors.New("autodns: missing user")
	}

	if config.Password == "" {
		return nil, errors.New("autodns: missing password")
	}

	client := internal.NewClient(config.Username, config.Password, config.Context)

	if config.Endpoint != nil {
		client.BaseURL = config.Endpoint
	}

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

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	records := []*internal.ResourceRecord{{
		Name:  info.EffectiveFQDN,
		TTL:   int64(d.config.TTL),
		Type:  "TXT",
		Value: info.Value,
	}}

	_, err := d.client.AddTxtRecords(context.Background(), info.EffectiveFQDN, records)
	if err != nil {
		return fmt.Errorf("autodns: %w", err)
	}

	return nil
}

// CleanUp removes the TXT record previously created.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	records := []*internal.ResourceRecord{{
		Name:  info.EffectiveFQDN,
		TTL:   int64(d.config.TTL),
		Type:  "TXT",
		Value: info.Value,
	}}

	if err := d.client.RemoveTXTRecords(context.Background(), info.EffectiveFQDN, records); err != nil {
		return fmt.Errorf("autodns: %w", err)
	}

	return nil
}
