// Package stackpath implements a DNS provider for solving the DNS-01 challenge using Stackpath DNS.
// https://developer.stackpath.com/en/api/dns/
package stackpath

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/platform/config/env"
	"legotoolbox/providers/dns/stackpath/internal"
)

// Environment variables names.
const (
	envNamespace = "STACKPATH_"

	EnvClientID     = envNamespace + "CLIENT_ID"
	EnvClientSecret = envNamespace + "CLIENT_SECRET"
	EnvStackID      = envNamespace + "STACK_ID"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	ClientID           string        `yaml:"clientID"`
	ClientSecret       string        `yaml:"clientSecret"`
	StackID            string        `yaml:"stackID"`
	TTL                int           `yaml:"ttl"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt(EnvTTL, 120),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, dns01.DefaultPropagationTimeout),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, dns01.DefaultPollingInterval),
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		TTL:                120,
		PropagationTimeout: dns01.DefaultPropagationTimeout,
		PollingInterval:    dns01.DefaultPollingInterval,
	}
}

func GetYamlTemple() string {
	return `# YAML 示例
clientID: "your_client_id_here"              # 客户端 ID，用于身份验证
clientSecret: "your_client_secret_here"      # 客户端密钥，用于身份验证
stackID: "your_stack_id_here"                # 堆栈 ID，用于标识特定的堆栈
ttl: 120                                     # TTL（Time to Live），表示数据或缓存的有效时间（以秒为单位）
propagationTimeout: 60s                      # 传播超时时间，表示系统等待变化传播的最长时间
pollingInterval: 2s                          # 轮询间隔时间，表示系统定期检查更新的时间间隔`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *internal.Client
}

// NewDNSProvider returns a DNSProvider instance configured for Stackpath.
// Credentials must be passed in the environment variables:
// STACKPATH_CLIENT_ID, STACKPATH_CLIENT_SECRET, and STACKPATH_STACK_ID.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvClientID, EnvClientSecret, EnvStackID)
	if err != nil {
		return nil, fmt.Errorf("stackpath: %w", err)
	}

	config := NewDefaultConfig()
	config.ClientID = values[EnvClientID]
	config.ClientSecret = values[EnvClientSecret]
	config.StackID = values[EnvStackID]

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

// NewDNSProviderConfig return a DNSProvider instance configured for Stackpath.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("stackpath: the configuration of the DNS provider is nil")
	}

	if config.ClientID == "" || config.ClientSecret == "" {
		return nil, errors.New("stackpath: credentials missing")
	}

	if config.StackID == "" {
		return nil, errors.New("stackpath: stack id missing")
	}

	client := internal.NewClient(context.Background(), config.StackID, config.ClientID, config.ClientSecret)

	return &DNSProvider{config: config, client: client}, nil
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	ctx := context.Background()

	zone, err := d.client.GetZones(ctx, info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("stackpath: %w", err)
	}

	subDomain, err := dns01.ExtractSubDomain(info.EffectiveFQDN, zone.Domain)
	if err != nil {
		return fmt.Errorf("stackpath: %w", err)
	}

	record := internal.Record{
		Name: subDomain,
		Type: "TXT",
		TTL:  d.config.TTL,
		Data: info.Value,
	}

	return d.client.CreateZoneRecord(ctx, zone, record)
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	ctx := context.Background()

	zone, err := d.client.GetZones(ctx, info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("stackpath: %w", err)
	}

	subDomain, err := dns01.ExtractSubDomain(info.EffectiveFQDN, zone.Domain)
	if err != nil {
		return fmt.Errorf("stackpath: %w", err)
	}

	records, err := d.client.GetZoneRecords(ctx, subDomain, zone)
	if err != nil {
		return err
	}

	for _, record := range records {
		err = d.client.DeleteZoneRecord(ctx, zone, record)
		if err != nil {
			log.Printf("stackpath: failed to delete TXT record: %v", err)
		}
	}

	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}
