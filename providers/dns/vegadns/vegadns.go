// Package vegadns implements a DNS provider for solving the DNS-01 challenge using VegaDNS.
package vegadns

import (
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"time"

	vegaClient "github.com/OpenDNS/vegadns2client"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
)

// Environment variables names.
const (
	envNamespace = "VEGADNS_"

	EnvKey    = "SECRET_VEGADNS_KEY"
	EnvSecret = "SECRET_VEGADNS_SECRET"
	EnvURL    = envNamespace + "URL"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	BaseURL            string        `yaml:"baseURL"`
	APIKey             string        `yaml:"apiKey"`
	APISecret          string        `yaml:"apiSecret"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	TTL                int           `yaml:"ttl"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt(EnvTTL, 10),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, 12*time.Minute),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, 1*time.Minute),
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		TTL:                10,
		PropagationTimeout: 12 * time.Minute,
		PollingInterval:    1 * time.Minute,
	}
}

func GetYamlTemple() string {
	return `# Config 是用来配置 DNSProvider 的创建。
baseURL: "https://api.example.com"    # BaseURL，API 的基础 URL
apiKey: "your_api_key"                # APIKey，API 访问密钥
apiSecret: "your_api_secret"          # APISecret，API 访问密钥的秘密
propagationTimeout: 720s              # PropagationTimeout，传播超时时间，指定更新记录后等待传播的最大时间，单位为秒（s）
pollingInterval: 60s                  # PollingInterval，轮询间隔时间，指定系统检查 DNS 记录状态的频率，单位为秒（s）
ttl: 10                               # TTL，DNS 记录的生存时间（秒）`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client vegaClient.VegaDNSClient
}

// NewDNSProvider returns a DNSProvider instance configured for VegaDNS.
// Credentials must be passed in the environment variables:
// VEGADNS_URL, SECRET_VEGADNS_KEY, SECRET_VEGADNS_SECRET.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvURL)
	if err != nil {
		return nil, fmt.Errorf("vegadns: %w", err)
	}

	config := NewDefaultConfig()
	config.BaseURL = values[EnvURL]
	config.APIKey = env.GetOrFile(EnvKey)
	config.APISecret = env.GetOrFile(EnvSecret)

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

// NewDNSProviderConfig return a DNSProvider instance configured for VegaDNS.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("vegadns: the configuration of the DNS provider is nil")
	}

	vega := vegaClient.NewVegaDNSClient(config.BaseURL)
	vega.APIKey = config.APIKey
	vega.APISecret = config.APISecret

	return &DNSProvider{client: vega, config: config}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	_, domainID, err := d.client.GetAuthZone(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("vegadns: can't find Authoritative Zone for %s in Present: %w", info.EffectiveFQDN, err)
	}

	err = d.client.CreateTXT(domainID, info.EffectiveFQDN, info.Value, d.config.TTL)
	if err != nil {
		return fmt.Errorf("vegadns: %w", err)
	}
	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	_, domainID, err := d.client.GetAuthZone(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("vegadns: can't find Authoritative Zone for %s in CleanUp: %w", info.EffectiveFQDN, err)
	}

	txt := dns01.UnFqdn(info.EffectiveFQDN)

	recordID, err := d.client.GetRecordID(domainID, txt, "TXT")
	if err != nil {
		return fmt.Errorf("vegadns: couldn't get Record ID in CleanUp: %w", err)
	}

	err = d.client.DeleteRecord(recordID)
	if err != nil {
		return fmt.Errorf("vegadns: %w", err)
	}
	return nil
}
