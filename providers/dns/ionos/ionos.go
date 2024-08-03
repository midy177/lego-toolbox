// Package ionos implements a DNS provider for solving the DNS-01 challenge using Ionos/1&1.
package ionos

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"lego-toolbox/providers/dns/ionos/internal"
)

const minTTL = 300

// Environment variables names.
const (
	envNamespace = "IONOS_"

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
		TTL:                env.GetOrDefaultInt(EnvTTL, minTTL),
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
		TTL:                minTTL,
		PropagationTimeout: dns01.DefaultPropagationTimeout,
		PollingInterval:    dns01.DefaultPollingInterval,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func GetYamlTemple() string {
	return `# YAML 示例
apiKey: "your_api_key_here"           # API 密钥，用于身份验证和授权
propagationTimeout: 60s               # 传播超时时间，表示系统等待变化传播的最长时间
pollingInterval: 2s                   # 轮询间隔时间，表示系统定期检查更新的时间间隔
ttl: 300                              # TTL（Time to Live），表示数据或缓存的有效时间（以秒为单位）`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *internal.Client
}

// NewDNSProvider returns a DNSProvider instance configured for Ionos.
// Credentials must be passed in the environment variables: IONOS_API_KEY.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvAPIKey)
	if err != nil {
		return nil, fmt.Errorf("ionos: %w", err)
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

// NewDNSProviderConfig return a DNSProvider instance configured for Ionos.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("ionos: the configuration of the DNS provider is nil")
	}

	if config.APIKey == "" {
		return nil, errors.New("ionos: credentials missing")
	}

	if config.TTL < minTTL {
		return nil, fmt.Errorf("ionos: invalid TTL, TTL (%d) must be greater than %d", config.TTL, minTTL)
	}

	client, err := internal.NewClient(config.APIKey)
	if err != nil {
		return nil, fmt.Errorf("ionos: %w", err)
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

// Present creates a TXT record using the specified parameters.
func (d *DNSProvider) Present(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	ctx := context.Background()

	zones, err := d.client.ListZones(ctx)
	if err != nil {
		return fmt.Errorf("ionos: failed to get zones: %w", err)
	}

	// TODO(ldez) replace domain by FQDN to follow CNAME.
	zone := findZone(zones, domain)
	if zone == nil {
		return errors.New("ionos: no matching zone found for domain")
	}

	filter := &internal.RecordsFilter{
		Suffix:     dns01.UnFqdn(info.EffectiveFQDN),
		RecordType: "TXT",
	}

	records, err := d.client.GetRecords(ctx, zone.ID, filter)
	if err != nil {
		return fmt.Errorf("ionos: failed to get records (zone=%s): %w", zone.ID, err)
	}

	records = append(records, internal.Record{
		Name:    dns01.UnFqdn(info.EffectiveFQDN),
		Content: info.Value,
		TTL:     d.config.TTL,
		Type:    "TXT",
	})

	err = d.client.ReplaceRecords(ctx, zone.ID, records)
	if err != nil {
		return fmt.Errorf("ionos: failed to create/update records (zone=%s): %w", zone.ID, err)
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	ctx := context.Background()

	zones, err := d.client.ListZones(ctx)
	if err != nil {
		return fmt.Errorf("ionos: failed to get zones: %w", err)
	}

	// TODO(ldez) replace domain by FQDN to follow CNAME.
	zone := findZone(zones, domain)
	if zone == nil {
		return errors.New("ionos: no matching zone found for domain")
	}

	filter := &internal.RecordsFilter{
		Suffix:     dns01.UnFqdn(info.EffectiveFQDN),
		RecordType: "TXT",
	}

	records, err := d.client.GetRecords(ctx, zone.ID, filter)
	if err != nil {
		return fmt.Errorf("ionos: failed to get records (zone=%s): %w", zone.ID, err)
	}

	for _, record := range records {
		if record.Name == dns01.UnFqdn(info.EffectiveFQDN) && record.Content == strconv.Quote(info.Value) {
			err = d.client.RemoveRecord(ctx, zone.ID, record.ID)
			if err != nil {
				return fmt.Errorf("ionos: failed to remove record (zone=%s, record=%s): %w", zone.ID, record.ID, err)
			}
			return nil
		}
	}

	return fmt.Errorf("ionos: failed to remove record, record not found (zone=%s, domain=%s, fqdn=%s, value=%s)", zone.ID, domain, info.EffectiveFQDN, info.Value)
}

func findZone(zones []internal.Zone, domain string) *internal.Zone {
	var result *internal.Zone

	for _, zone := range zones {
		if zone.Name != "" && strings.HasSuffix(domain, zone.Name) {
			if result == nil || len(zone.Name) > len(result.Name) {
				result = &zone
			}
		}
	}

	return result
}
