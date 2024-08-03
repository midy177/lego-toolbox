// Package hosttech implements a DNS provider for solving the DNS-01 challenge using hosttech.
package hosttech

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
	"lego-toolbox/providers/dns/hosttech/internal"
)

// Environment variables names.
const (
	envNamespace = "HOSTTECH_"

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
	return `# Config is used to configure the creation of the DNSProvider.
apiKey: "your_api_key"          # API 密钥，用于对 API 请求进行身份验证
propagationTimeout: 60s         # DNS 记录传播超时时间，指定更新记录后等待传播的最大时间，单位为秒（s）
pollingInterval: 2s             # 轮询间隔时间，指定系统检查 DNS 记录状态的频率，单位为秒（s）
ttl: 3600                       # DNS 记录的生存时间（TTL），表示记录在 DNS 缓存中的有效时间，单位为秒（s）
`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *internal.Client

	recordIDs   map[string]int
	recordIDsMu sync.Mutex
}

// NewDNSProvider returns a DNSProvider instance configured for hosttech.
// Credentials must be passed in the environment variable: HOSTTECH_API_KEY.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvAPIKey)
	if err != nil {
		return nil, fmt.Errorf("hosttech: %w", err)
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

// NewDNSProviderConfig return a DNSProvider instance configured for hosttech.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("hosttech: the configuration of the DNS provider is nil")
	}

	if config.APIKey == "" {
		return nil, errors.New("hosttech: missing credentials")
	}

	client := internal.NewClient(internal.OAuthStaticAccessToken(config.HTTPClient, config.APIKey))

	return &DNSProvider{
		config:    config,
		client:    client,
		recordIDs: map[string]int{},
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

	authZone, err := dns01.FindZoneByFqdn(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("hosttech: could not find zone for domain %q: %w", domain, err)
	}

	ctx := context.Background()

	zone, err := d.client.GetZone(ctx, dns01.UnFqdn(authZone))
	if err != nil {
		return fmt.Errorf("hosttech: could not find zone for domain %q (%s): %w", domain, authZone, err)
	}

	subDomain, err := dns01.ExtractSubDomain(info.EffectiveFQDN, authZone)
	if err != nil {
		return fmt.Errorf("hosttech: %w", err)
	}

	record := internal.Record{
		Type: "TXT",
		Name: subDomain,
		Text: info.Value,
		TTL:  d.config.TTL,
	}

	newRecord, err := d.client.AddRecord(ctx, strconv.Itoa(zone.ID), record)
	if err != nil {
		return fmt.Errorf("hosttech: %w", err)
	}

	d.recordIDsMu.Lock()
	d.recordIDs[token] = newRecord.ID
	d.recordIDsMu.Unlock()

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	authZone, err := dns01.FindZoneByFqdn(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("hosttech: could not find zone for domain %q: %w", domain, err)
	}

	ctx := context.Background()

	zone, err := d.client.GetZone(ctx, dns01.UnFqdn(authZone))
	if err != nil {
		return fmt.Errorf("hosttech: could not find zone for domain %q (%s): %w", domain, authZone, err)
	}

	// gets the record's unique ID from when we created it
	d.recordIDsMu.Lock()
	recordID, ok := d.recordIDs[token]
	d.recordIDsMu.Unlock()
	if !ok {
		return fmt.Errorf("hosttech: unknown record ID for '%s' '%s'", info.EffectiveFQDN, token)
	}

	err = d.client.DeleteRecord(ctx, strconv.Itoa(zone.ID), strconv.Itoa(recordID))
	if err != nil {
		return fmt.Errorf("hosttech: %w", err)
	}

	return nil
}
