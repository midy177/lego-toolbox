// Package cloudns implements a DNS provider for solving the DNS-01 challenge using ClouDNS DNS.
package cloudns

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/go-acme/lego/v4/platform/wait"
	"lego-toolbox/providers/dns/cloudns/internal"
)

// Environment variables names.
const (
	envNamespace = "CLOUDNS_"

	EnvAuthID       = envNamespace + "AUTH_ID"
	EnvSubAuthID    = envNamespace + "SUB_AUTH_ID"
	EnvAuthPassword = envNamespace + "AUTH_PASSWORD"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	AuthID             string        `yaml:"authID"`
	SubAuthID          string        `yaml:"subAuthID"`
	AuthPassword       string        `yaml:"authPassword"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	TTL                int           `yaml:"ttl"`
	HTTPClient         *http.Client  `yaml:"-"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt(EnvTTL, 60),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, 180*time.Second),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, 10*time.Second),
		HTTPClient: &http.Client{
			Timeout: env.GetOrDefaultSecond(EnvHTTPTimeout, 30*time.Second),
		},
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		TTL:                60,
		PropagationTimeout: 180 * time.Second,
		PollingInterval:    10 * time.Second,
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

// NewDNSProvider returns a DNSProvider instance configured for ClouDNS.
// Credentials must be passed in the environment variables:
// CLOUDNS_AUTH_ID and CLOUDNS_AUTH_PASSWORD.
func NewDNSProvider() (*DNSProvider, error) {
	var subAuthID string
	authID := env.GetOrFile(EnvAuthID)
	if authID == "" {
		subAuthID = env.GetOrFile(EnvSubAuthID)
	}

	if authID == "" && subAuthID == "" {
		return nil, fmt.Errorf("ClouDNS: some credentials information are missing: %s or %s", EnvAuthID, EnvSubAuthID)
	}

	values, err := env.Get(EnvAuthPassword)
	if err != nil {
		return nil, fmt.Errorf("ClouDNS: %w", err)
	}

	config := NewDefaultConfig()
	config.AuthID = authID
	config.SubAuthID = subAuthID
	config.AuthPassword = values[EnvAuthPassword]

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

// NewDNSProviderConfig return a DNSProvider instance configured for ClouDNS.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("ClouDNS: the configuration of the DNS provider is nil")
	}

	client, err := internal.NewClient(config.AuthID, config.SubAuthID, config.AuthPassword)
	if err != nil {
		return nil, fmt.Errorf("ClouDNS: %w", err)
	}

	client.HTTPClient = config.HTTPClient

	return &DNSProvider{client: client, config: config}, nil
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	ctx := context.Background()

	zone, err := d.client.GetZone(ctx, info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("ClouDNS: %w", err)
	}

	err = d.client.AddTxtRecord(ctx, zone.Name, info.EffectiveFQDN, info.Value, d.config.TTL)
	if err != nil {
		return fmt.Errorf("ClouDNS: %w", err)
	}

	return d.waitNameservers(ctx, domain, zone)
}

// CleanUp removes the TXT records matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	ctx := context.Background()

	zone, err := d.client.GetZone(ctx, info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("ClouDNS: %w", err)
	}

	records, err := d.client.ListTxtRecords(ctx, zone.Name, info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("ClouDNS: %w", err)
	}

	if len(records) == 0 {
		return nil
	}

	for _, record := range records {
		err = d.client.RemoveTxtRecord(ctx, record.ID, zone.Name)
		if err != nil {
			return fmt.Errorf("ClouDNS: %w", err)
		}
	}

	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// waitNameservers At the time of writing 4 servers are found as authoritative, but 8 are reported during the sync.
// If this is not done, the secondary verification done by Let's Encrypt server will fail quire a bit.
func (d *DNSProvider) waitNameservers(ctx context.Context, domain string, zone *internal.Zone) error {
	return wait.For("Nameserver sync on "+domain, d.config.PropagationTimeout, d.config.PollingInterval, func() (bool, error) {
		syncProgress, err := d.client.GetUpdateStatus(ctx, zone.Name)
		if err != nil {
			return false, err
		}

		log.Infof("[%s] Sync %d/%d complete", domain, syncProgress.Updated, syncProgress.Total)

		return syncProgress.Complete, nil
	})
}
