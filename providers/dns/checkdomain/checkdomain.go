// Package checkdomain implements a DNS provider for solving the DNS-01 challenge using CheckDomain DNS.
package checkdomain

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
	"lego-toolbox/providers/dns/checkdomain/internal"
)

// Environment variables names.
const (
	envNamespace = "CHECKDOMAIN_"

	EnvEndpoint = envNamespace + "ENDPOINT"
	EnvToken    = envNamespace + "TOKEN"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	Endpoint           *url.URL      `yaml:"-"`
	EndpointUrl        string        `yaml:"endpoint"`
	Token              string        `yaml:"token"`
	TTL                int           `yaml:"ttl"`
	PropagationTimeout time.Duration `yaml:"PropagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	HTTPClient         *http.Client  `yaml:"-"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt(EnvTTL, 300),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, 5*time.Minute),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, 7*time.Second),
		HTTPClient: &http.Client{
			Timeout: env.GetOrDefaultSecond(EnvHTTPTimeout, 30*time.Second),
		},
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		TTL:                300,
		PropagationTimeout: 5 * time.Minute,
		PollingInterval:    7 * time.Second,
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

// NewDNSProvider returns a DNSProvider instance configured for CheckDomain.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvToken)
	if err != nil {
		return nil, fmt.Errorf("checkdomain: %w", err)
	}

	config := NewDefaultConfig()
	config.Token = values[EnvToken]

	endpoint, err := url.Parse(env.GetOrDefaultString(EnvEndpoint, internal.DefaultEndpoint))
	if err != nil {
		return nil, fmt.Errorf("checkdomain: invalid %s: %w", EnvEndpoint, err)
	}
	config.Endpoint = endpoint

	return NewDNSProviderConfig(config)
}

// ParseConfig parse bytes to config
func ParseConfig(rawConfig []byte) (*Config, error) {
	config := DefaultConfig()
	err := yaml.Unmarshal(rawConfig, &config)
	if err != nil {
		return nil, err
	}
	if config.EndpointUrl != "" {
		endpoint, err := url.Parse(config.EndpointUrl)
		if err != nil {
			return nil, fmt.Errorf("checkdomain: invalid %s: %w", config.EndpointUrl, err)
		}
		config.Endpoint = endpoint
	} else {
		endpoint, err := url.Parse(internal.DefaultEndpoint)
		if err != nil {
			return nil, fmt.Errorf("checkdomain: invalid %s: %w", internal.DefaultEndpoint, err)
		}
		config.Endpoint = endpoint
	}
	return config, nil
}

func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config.Endpoint == nil {
		return nil, errors.New("checkdomain: invalid endpoint")
	}

	if config.Token == "" {
		return nil, errors.New("checkdomain: missing token")
	}

	client := internal.NewClient(internal.OAuthStaticAccessToken(config.HTTPClient, config.Token))

	if config.Endpoint != nil {
		client.BaseURL = config.Endpoint
	}

	return &DNSProvider{config: config, client: client}, nil
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	ctx := context.Background()

	// TODO(ldez) replace domain by FQDN to follow CNAME.
	domainID, err := d.client.GetDomainIDByName(ctx, domain)
	if err != nil {
		return fmt.Errorf("checkdomain: %w", err)
	}

	err = d.client.CheckNameservers(ctx, domainID)
	if err != nil {
		return fmt.Errorf("checkdomain: %w", err)
	}

	info := dns01.GetChallengeInfo(domain, keyAuth)

	err = d.client.CreateRecord(ctx, domainID, &internal.Record{
		Name:  info.EffectiveFQDN,
		TTL:   d.config.TTL,
		Type:  "TXT",
		Value: info.Value,
	})
	if err != nil {
		return fmt.Errorf("checkdomain: %w", err)
	}

	return nil
}

// CleanUp removes the TXT record previously created.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	ctx := context.Background()

	// TODO(ldez) replace domain by FQDN to follow CNAME.
	domainID, err := d.client.GetDomainIDByName(ctx, domain)
	if err != nil {
		return fmt.Errorf("checkdomain: %w", err)
	}

	err = d.client.CheckNameservers(ctx, domainID)
	if err != nil {
		return fmt.Errorf("checkdomain: %w", err)
	}

	info := dns01.GetChallengeInfo(domain, keyAuth)

	defer d.client.CleanCache(info.EffectiveFQDN)

	err = d.client.DeleteTXTRecord(ctx, domainID, info.EffectiveFQDN, info.Value)
	if err != nil {
		return fmt.Errorf("checkdomain: %w", err)
	}

	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}
