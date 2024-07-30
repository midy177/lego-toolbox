// Package yandex implements a DNS provider for solving the DNS-01 challenge using Yandex PDD.
package yandex

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/miekg/dns"
	"legotoolbox/providers/dns/yandex/internal"
)

// Environment variables names.
const (
	envNamespace = "YANDEX_"

	EnvPddToken = envNamespace + "PDD_TOKEN"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	PddToken           string        `yaml:"pddToken"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	TTL                int           `yaml:"ttl"`
	HTTPClient         *http.Client  `yaml:"-"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt(EnvTTL, 21600),
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
		TTL:                21600,
		PropagationTimeout: dns01.DefaultPropagationTimeout,
		PollingInterval:    dns01.DefaultPollingInterval,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func GetYamlTemple() string {
	return `# config.yaml
pddToken: "your_pdd_token"                  # Pdd 令牌
propagationTimeout: 60s                     # 传播超时时间，单位为秒
pollingInterval: 2s                         # 轮询间隔时间，单位为秒
ttl: 21600                                  # TTL 值，单位为秒`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	client *internal.Client
	config *Config
}

// NewDNSProvider returns a DNSProvider instance configured for Yandex.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvPddToken)
	if err != nil {
		return nil, fmt.Errorf("yandex: %w", err)
	}

	config := NewDefaultConfig()
	config.PddToken = values[EnvPddToken]

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

// NewDNSProviderConfig return a DNSProvider instance configured for Yandex.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("yandex: the configuration of the DNS provider is nil")
	}

	if config.PddToken == "" {
		return nil, errors.New("yandex: credentials missing")
	}

	client, err := internal.NewClient(config.PddToken)
	if err != nil {
		return nil, fmt.Errorf("yandex: %w", err)
	}

	if config.HTTPClient != nil {
		client.HTTPClient = config.HTTPClient
	}

	return &DNSProvider{client: client, config: config}, nil
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	rootDomain, subDomain, err := splitDomain(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("yandex: %w", err)
	}

	data := internal.Record{
		Domain:    rootDomain,
		SubDomain: subDomain,
		Type:      "TXT",
		TTL:       d.config.TTL,
		Content:   info.Value,
	}

	_, err = d.client.AddRecord(context.Background(), data)
	if err != nil {
		return fmt.Errorf("yandex: %w", err)
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	rootDomain, subDomain, err := splitDomain(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("yandex: %w", err)
	}

	ctx := context.Background()

	records, err := d.client.GetRecords(ctx, rootDomain)
	if err != nil {
		return fmt.Errorf("yandex: %w", err)
	}

	var record *internal.Record
	for _, rcd := range records {
		if rcd.Type == "TXT" && rcd.SubDomain == subDomain && rcd.Content == info.Value {
			record = &rcd
			break
		}
	}

	if record == nil {
		return fmt.Errorf("yandex: TXT record not found for domain: %s", domain)
	}

	data := internal.Record{
		ID:     record.ID,
		Domain: rootDomain,
	}

	_, err = d.client.RemoveRecord(ctx, data)
	if err != nil {
		return fmt.Errorf("yandex: %w", err)
	}
	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

func splitDomain(full string) (string, string, error) {
	split := dns.Split(full)
	if len(split) < 2 {
		return "", "", fmt.Errorf("unsupported domain: %s", full)
	}

	if len(split) == 2 {
		return full, "", nil
	}

	domain := full[split[len(split)-2]:]
	subDomain := full[:split[len(split)-2]-1]

	return domain, subDomain, nil
}
