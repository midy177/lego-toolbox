// Package cloudru implements a DNS provider for solving the DNS-01 challenge using cloud.ru DNS.
package cloudru

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"lego-toolbox/providers/dns/cloudru/internal"
)

// Environment variables names.
const (
	envNamespace = "CLOUDRU_"

	EnvServiceInstanceID = envNamespace + "SERVICE_INSTANCE_ID"
	EnvKeyID             = envNamespace + "KEY_ID"
	EnvSecret            = envNamespace + "SECRET"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvSequenceInterval   = envNamespace + "SEQUENCE_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	ServiceInstanceID  string        `yaml:"serviceInstanceID"`
	KeyID              string        `yaml:"keyID"`
	Secret             string        `yaml:"secret"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	SequenceInterval   time.Duration `yaml:"sequenceInterval"`
	HTTPClient         *http.Client  `yaml:"-"`
	TTL                int           `yaml:"ttl"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt(EnvTTL, dns01.DefaultTTL),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, 5*time.Minute),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, 5*time.Second),
		SequenceInterval:   env.GetOrDefaultSecond(EnvSequenceInterval, dns01.DefaultPropagationTimeout),
		HTTPClient: &http.Client{
			Timeout: env.GetOrDefaultSecond(EnvHTTPTimeout, 30*time.Second),
		},
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		TTL:                dns01.DefaultTTL,
		PropagationTimeout: 5 * time.Minute,
		PollingInterval:    5 * time.Second,
		SequenceInterval:   dns01.DefaultPropagationTimeout,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

type DNSProvider struct {
	config    *Config
	client    *internal.Client
	records   map[string]*internal.Record
	recordsMu sync.Mutex
}

// NewDNSProvider returns a DNSProvider instance configured for cloud.ru.
// Credentials must be passed in the environment variables:
// CLOUDRU_SERVICE_INSTANCE_ID, CLOUDRU_KEY_ID, and CLOUDRU_SECRET.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvServiceInstanceID, EnvKeyID, EnvSecret)
	if err != nil {
		return nil, fmt.Errorf("cloudru: %w", err)
	}

	config := NewDefaultConfig()
	config.ServiceInstanceID = values[EnvServiceInstanceID]
	config.KeyID = values[EnvKeyID]
	config.Secret = values[EnvSecret]

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

// NewDNSProviderConfig return a DNSProvider instance configured for cloud.ru.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("cloudru: the configuration of the DNS provider is nil")
	}

	if config.ServiceInstanceID == "" || config.KeyID == "" || config.Secret == "" {
		return nil, errors.New("cloudru: some credentials information are missing")
	}

	client := internal.NewClient(config.KeyID, config.Secret)

	if config.HTTPClient != nil {
		client.HTTPClient = config.HTTPClient
	}

	return &DNSProvider{
		config:  config,
		client:  client,
		records: make(map[string]*internal.Record),
	}, nil
}

// Present creates a TXT record using the specified parameters.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	authZone, err := dns01.FindZoneByFqdn(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("cloudru: could not find zone for domain %q: %w", domain, err)
	}

	authZone = dns01.UnFqdn(authZone)

	ctx, err := d.client.CreateAuthenticatedContext(context.Background())
	if err != nil {
		return fmt.Errorf("cloudru: %w", err)
	}

	zone, err := d.getZoneInformationByName(ctx, d.config.ServiceInstanceID, authZone)
	if err != nil {
		return fmt.Errorf("cloudru: could not find zone information (ServiceInstanceID: %s, zone: %s): %w", d.config.ServiceInstanceID, authZone, err)
	}

	record := internal.Record{
		Name:   info.EffectiveFQDN,
		Type:   "TXT",
		Values: []string{info.Value},
		TTL:    strconv.Itoa(d.config.TTL),
	}

	newRecord, err := d.client.CreateRecord(ctx, zone.ID, record)
	if err != nil {
		return fmt.Errorf("cloudru: could not create record: %w", err)
	}

	d.recordsMu.Lock()
	d.records[token] = newRecord
	d.recordsMu.Unlock()

	return nil
}

// CleanUp removes a given record that was generated by Present.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	d.recordsMu.Lock()
	record, ok := d.records[token]
	d.recordsMu.Unlock()

	if !ok {
		return fmt.Errorf("cloudru: unknown recordID for %q", info.EffectiveFQDN)
	}

	ctx, err := d.client.CreateAuthenticatedContext(context.Background())
	if err != nil {
		return fmt.Errorf("cloudru: %w", err)
	}

	err = d.client.DeleteRecord(ctx, record.ZoneID, record.Name, "TXT")
	if err != nil {
		return fmt.Errorf("cloudru: %w", err)
	}

	d.recordsMu.Lock()
	delete(d.records, token)
	d.recordsMu.Unlock()

	return nil
}

// Sequential All DNS challenges for this provider will be resolved sequentially.
// Returns the interval between each iteration.
func (d *DNSProvider) Sequential() time.Duration {
	return d.config.SequenceInterval
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

func (d *DNSProvider) getZoneInformationByName(ctx context.Context, parentID, name string) (internal.Zone, error) {
	zs, err := d.client.GetZones(ctx, parentID)
	if err != nil {
		return internal.Zone{}, err
	}

	for _, element := range zs {
		if element.Name == name {
			return element, nil
		}
	}

	return internal.Zone{}, errors.New("could not find Zone record")
}
