// Package vscale implements a DNS provider for solving the DNS-01 challenge using Vscale Domains API.
// Vscale Domain API reference: https://developers.vscale.io/documentation/api/v1/#api-Domains
// Token: https://vscale.io/panel/settings/tokens/
package vscale

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
	"lego-toolbox/providers/dns/internal/selectel"
)

const minTTL = 60

// Environment variables names.
const (
	envNamespace = "VSCALE_"

	EnvBaseURL  = envNamespace + "BASE_URL"
	EnvAPIToken = envNamespace + "API_TOKEN"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	BaseURL            string        `yaml:"baseURL"`
	Token              string        `yaml:"token"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	TTL                int           `yaml:"ttl"`
	HTTPClient         *http.Client  `yaml:"-"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		BaseURL:            env.GetOrDefaultString(EnvBaseURL, selectel.DefaultVScaleBaseURL),
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
		BaseURL:            selectel.DefaultVScaleBaseURL,
		TTL:                minTTL,
		PropagationTimeout: 120 * time.Second,
		PollingInterval:    2 * time.Second,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func GetYamlTemple() string {
	return `# Config 是用来配置 DNSProvider 的创建。
baseURL: "https://api.vscale.io/v1/domains"    # BaseURL，用于与服务提供商通信的基础 URL
token: "your_api_token"               # Token，API 访问令牌，用于身份验证
propagationTimeout: 120s              # PropagationTimeout，传播超时时间，指定更新记录后等待传播的最大时间，单位为秒（s）
pollingInterval: 2s                   # PollingInterval，轮询间隔时间，指定系统检查 DNS 记录状态的频率，单位为秒（s）
ttl: 60                               # TTL，DNS 记录的生存时间（秒）
`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *selectel.Client
}

// NewDNSProvider returns a DNSProvider instance configured for Vscale Domains API.
// API token must be passed in the environment variable VSCALE_API_TOKEN.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvAPIToken)
	if err != nil {
		return nil, fmt.Errorf("vscale: %w", err)
	}

	config := NewDefaultConfig()
	config.Token = values[EnvAPIToken]

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

// NewDNSProviderConfig return a DNSProvider instance configured for Vscale.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("vscale: the configuration of the DNS provider is nil")
	}

	if config.Token == "" {
		return nil, errors.New("vscale: credentials missing")
	}

	if config.TTL < minTTL {
		return nil, fmt.Errorf("vscale: invalid TTL, TTL (%d) must be greater than %d", config.TTL, minTTL)
	}

	client := selectel.NewClient(config.Token)
	if config.HTTPClient != nil {
		client.HTTPClient = config.HTTPClient
	}

	var err error
	client.BaseURL, err = url.Parse(config.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("vscale: %w", err)
	}

	return &DNSProvider{config: config, client: client}, nil
}

// Timeout returns the Timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// Present creates a TXT record to fulfill DNS-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	ctx := context.Background()

	// TODO(ldez) replace domain by FQDN to follow CNAME.
	domainObj, err := d.client.GetDomainByName(ctx, domain)
	if err != nil {
		return fmt.Errorf("vscale: %w", err)
	}

	txtRecord := selectel.Record{
		Type:    "TXT",
		TTL:     d.config.TTL,
		Name:    info.EffectiveFQDN,
		Content: info.Value,
	}
	_, err = d.client.AddRecord(ctx, domainObj.ID, txtRecord)
	if err != nil {
		return fmt.Errorf("vscale: %w", err)
	}

	return nil
}

// CleanUp removes a TXT record used for DNS-01 challenge.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	recordName := dns01.UnFqdn(info.EffectiveFQDN)

	ctx := context.Background()

	// TODO(ldez) replace domain by FQDN to follow CNAME.
	domainObj, err := d.client.GetDomainByName(ctx, domain)
	if err != nil {
		return fmt.Errorf("vscale: %w", err)
	}

	records, err := d.client.ListRecords(ctx, domainObj.ID)
	if err != nil {
		return fmt.Errorf("vscale: %w", err)
	}

	// Delete records with specific FQDN
	var lastErr error
	for _, record := range records {
		if record.Name == recordName {
			err = d.client.DeleteRecord(ctx, domainObj.ID, record.ID)
			if err != nil {
				lastErr = fmt.Errorf("vscale: %w", err)
			}
		}
	}

	return lastErr
}
