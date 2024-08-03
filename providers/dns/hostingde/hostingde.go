// Package hostingde implements a DNS provider for solving the DNS-01 challenge using hosting.de.
package hostingde

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"lego-toolbox/providers/dns/internal/hostingde"
)

// Environment variables names.
const (
	envNamespace = "HOSTINGDE_"

	EnvAPIKey   = envNamespace + "API_KEY"
	EnvZoneName = envNamespace + "ZONE_NAME"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	APIKey             string        `yaml:"apiKey"`
	ZoneName           string        `yaml:"zoneName"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	TTL                int           `yaml:"ttl"`
	HTTPClient         *http.Client  `yaml:"-"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		ZoneName:           env.GetOrFile(EnvZoneName),
		TTL:                env.GetOrDefaultInt(EnvTTL, dns01.DefaultTTL),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, 2*time.Minute),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, 2*time.Second),
		HTTPClient: &http.Client{
			Timeout: env.GetOrDefaultSecond(EnvHTTPTimeout, 30*time.Second),
		},
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		//ZoneName:           env.GetOrFile(EnvZoneName),
		TTL:                dns01.DefaultTTL,
		PropagationTimeout: 2 * time.Minute,
		PollingInterval:    2 * time.Second,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func GetYamlTemple() string {
	return `# Config is used to configure the creation of the DNSProvider.
apiKey: "your_api_key"          # API 密钥，用于对 API 请求进行身份验证
zoneName: "example.com"         # DNS 区域名称，指定要管理的 DNS 区域的名称
propagationTimeout: 120s        # 记录传播超时时间，指定 DNS 记录更新后等待传播的最大时间，单位为秒
pollingInterval: 2s             # 轮询间隔时间，指定系统多久检查一次 DNS 记录的状态，单位为秒
ttl: 120                        # DNS 记录的生存时间（TTL），表示记录在 DNS 缓存中的有效时间，单位为秒`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *hostingde.Client

	recordIDs   map[string]string
	recordIDsMu sync.Mutex
}

// NewDNSProvider returns a DNSProvider instance configured for hosting.de.
// Credentials must be passed in the environment variables:
// HOSTINGDE_ZONE_NAME and HOSTINGDE_API_KEY.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvAPIKey)
	if err != nil {
		return nil, fmt.Errorf("hostingde: %w", err)
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

// NewDNSProviderConfig return a DNSProvider instance configured for hosting.de.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("hostingde: the configuration of the DNS provider is nil")
	}

	if config.APIKey == "" {
		return nil, errors.New("hostingde: API key missing")
	}

	return &DNSProvider{
		config:    config,
		client:    hostingde.NewClient(config.APIKey),
		recordIDs: make(map[string]string),
	}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	zoneName, err := d.getZoneName(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("hostingde: could not find zone for domain %q: %w", domain, err)
	}

	ctx := context.Background()

	// get the ZoneConfig for that domain
	zonesFind := hostingde.ZoneConfigsFindRequest{
		Filter: hostingde.Filter{Field: "zoneName", Value: zoneName},
		Limit:  1,
		Page:   1,
	}

	zoneConfig, err := d.client.GetZone(ctx, zonesFind)
	if err != nil {
		return fmt.Errorf("hostingde: %w", err)
	}

	zoneConfig.Name = zoneName

	rec := []hostingde.DNSRecord{{
		Type:    "TXT",
		Name:    dns01.UnFqdn(info.EffectiveFQDN),
		Content: info.Value,
		TTL:     d.config.TTL,
	}}

	req := hostingde.ZoneUpdateRequest{
		ZoneConfig:   *zoneConfig,
		RecordsToAdd: rec,
	}

	response, err := d.client.UpdateZone(ctx, req)
	if err != nil {
		return fmt.Errorf("hostingde: %w", err)
	}

	for _, record := range response.Records {
		if record.Name == dns01.UnFqdn(info.EffectiveFQDN) && record.Content == fmt.Sprintf(`%q`, info.Value) {
			d.recordIDsMu.Lock()
			d.recordIDs[info.EffectiveFQDN] = record.ID
			d.recordIDsMu.Unlock()
		}
	}

	if d.recordIDs[info.EffectiveFQDN] == "" {
		return fmt.Errorf("hostingde: error getting ID of just created record, for domain %s", domain)
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	zoneName, err := d.getZoneName(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("hostingde: could not find zone for domain %q: %w", domain, err)
	}

	ctx := context.Background()

	// get the ZoneConfig for that domain
	zonesFind := hostingde.ZoneConfigsFindRequest{
		Filter: hostingde.Filter{Field: "zoneName", Value: zoneName},
		Limit:  1,
		Page:   1,
	}

	zoneConfig, err := d.client.GetZone(ctx, zonesFind)
	if err != nil {
		return fmt.Errorf("hostingde: %w", err)
	}
	zoneConfig.Name = zoneName

	rec := []hostingde.DNSRecord{{
		Type:    "TXT",
		Name:    dns01.UnFqdn(info.EffectiveFQDN),
		Content: `"` + info.Value + `"`,
	}}

	req := hostingde.ZoneUpdateRequest{
		ZoneConfig:      *zoneConfig,
		RecordsToDelete: rec,
	}

	// Delete record ID from map
	d.recordIDsMu.Lock()
	delete(d.recordIDs, info.EffectiveFQDN)
	d.recordIDsMu.Unlock()

	_, err = d.client.UpdateZone(ctx, req)
	if err != nil {
		return fmt.Errorf("hostingde: %w", err)
	}
	return nil
}

func (d *DNSProvider) getZoneName(fqdn string) (string, error) {
	if d.config.ZoneName != "" {
		return d.config.ZoneName, nil
	}

	zoneName, err := dns01.FindZoneByFqdn(fqdn)
	if err != nil {
		return "", fmt.Errorf("could not find zone for %s: %w", fqdn, err)
	}

	if zoneName == "" {
		return "", errors.New("empty zone name")
	}

	return dns01.UnFqdn(zoneName), nil
}
