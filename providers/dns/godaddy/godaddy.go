// Package godaddy implements a DNS provider for solving the DNS-01 challenge using godaddy DNS.
package godaddy

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"legotoolbox/providers/dns/godaddy/internal"
)

const minTTL = 600

// Environment variables names.
const (
	envNamespace = "GODADDY_"

	EnvAPIKey    = envNamespace + "API_KEY"
	EnvAPISecret = envNamespace + "API_SECRET"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	APIKey             string        `yaml:"apiKey"`
	APISecret          string        `yaml:"apiSecret"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	TTL                int           `yaml:"ttl"`
	HTTPClient         *http.Client  `yaml:"-"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt(EnvTTL, minTTL),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, 120*time.Second),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, 2*time.Second),
		HTTPClient: &http.Client{
			Timeout: env.GetOrDefaultSecond(EnvHTTPTimeout, 30*time.Second),
		},
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		TTL:                minTTL,
		PropagationTimeout: 120 * time.Second,
		PollingInterval:    2 * time.Second,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func GetYamlTemple() string {
	return `# Config is used to configure the creation of the DNSProvider.
apiKey: "your_api_key"       # API 密钥，用于认证和授权访问 DNS 服务
apiSecret: "your_api_secret" # API 密钥的秘密部分，用于认证
propagationTimeout: 120s     # 传播超时时间，表示 DNS 记录更新后等待传播的最大时间，单位为秒
pollingInterval: 2s          # 轮询间隔，表示检查 DNS 记录状态的时间间隔，单位为秒
ttl: 600                     # DNS 记录的生存时间（TTL），单位为秒，表示记录在缓存中存活的时间`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *internal.Client
}

// NewDNSProvider returns a DNSProvider instance configured for godaddy.
// Credentials must be passed in the environment variables:
// GODADDY_API_KEY and GODADDY_API_SECRET.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvAPIKey, EnvAPISecret)
	if err != nil {
		return nil, fmt.Errorf("godaddy: %w", err)
	}

	config := NewDefaultConfig()
	config.APIKey = values[EnvAPIKey]
	config.APISecret = values[EnvAPISecret]

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

// NewDNSProviderConfig return a DNSProvider instance configured for godaddy.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("godaddy: the configuration of the DNS provider is nil")
	}

	if config.APIKey == "" || config.APISecret == "" {
		return nil, errors.New("godaddy: credentials missing")
	}

	if config.TTL < minTTL {
		return nil, fmt.Errorf("godaddy: invalid TTL, TTL (%d) must be greater than %d", config.TTL, minTTL)
	}

	client := internal.NewClient(config.APIKey, config.APISecret)

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

	authZone, err := dns01.FindZoneByFqdn(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("godaddy: could not find zone for domain %q: %w", domain, err)
	}

	authZone = dns01.UnFqdn(authZone)

	subDomain, err := dns01.ExtractSubDomain(info.EffectiveFQDN, authZone)
	if err != nil {
		return fmt.Errorf("godaddy: %w", err)
	}

	ctx := context.Background()

	records, err := d.client.GetRecords(ctx, authZone, "TXT", subDomain)
	if err != nil {
		return fmt.Errorf("godaddy: failed to get TXT records: %w", err)
	}

	var newRecords []internal.DNSRecord
	for _, record := range records {
		if record.Data != "" {
			newRecords = append(newRecords, record)
		}
	}

	record := internal.DNSRecord{
		Type: "TXT",
		Name: subDomain,
		Data: info.Value,
		TTL:  d.config.TTL,
	}
	newRecords = append(newRecords, record)

	err = d.client.UpdateTxtRecords(ctx, newRecords, authZone, subDomain)
	if err != nil {
		return fmt.Errorf("godaddy: failed to add TXT record: %w", err)
	}

	return nil
}

// CleanUp removes the record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	authZone, err := dns01.FindZoneByFqdn(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("godaddy: could not find zone for domain %q: %w", domain, err)
	}

	authZone = dns01.UnFqdn(authZone)

	subDomain, err := dns01.ExtractSubDomain(info.EffectiveFQDN, authZone)
	if err != nil {
		return fmt.Errorf("godaddy: %w", err)
	}

	ctx := context.Background()

	records, err := d.client.GetRecords(ctx, authZone, "TXT", subDomain)
	if err != nil {
		return fmt.Errorf("godaddy: failed to get TXT records: %w", err)
	}

	if len(records) == 0 {
		return nil
	}

	allTxtRecords, err := d.client.GetRecords(ctx, authZone, "TXT", "")
	if err != nil {
		return fmt.Errorf("godaddy: failed to get all TXT records: %w", err)
	}

	var recordsKeep []internal.DNSRecord
	for _, record := range allTxtRecords {
		if record.Data != info.Value && record.Data != "" {
			recordsKeep = append(recordsKeep, record)
		}
	}

	// GoDaddy API don't provide a way to delete a record, an "empty" record must be added.
	if len(recordsKeep) == 0 {
		emptyRecord := internal.DNSRecord{Name: "empty", Data: ""}
		recordsKeep = append(recordsKeep, emptyRecord)
	}

	err = d.client.UpdateTxtRecords(ctx, recordsKeep, authZone, "")
	if err != nil {
		return fmt.Errorf("godaddy: failed to remove TXT record: %w", err)
	}

	return nil
}
