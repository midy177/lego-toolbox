// Package ultradns implements a DNS provider for solving the DNS-01 challenge using ultradns.
package ultradns

import (
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/ultradns/ultradns-go-sdk/pkg/client"
	"github.com/ultradns/ultradns-go-sdk/pkg/record"
	"github.com/ultradns/ultradns-go-sdk/pkg/rrset"
)

// Environment variables names.
const (
	envNamespace = "ULTRADNS_"

	EnvUsername = envNamespace + "USERNAME"
	EnvPassword = envNamespace + "PASSWORD"
	EnvEndpoint = envNamespace + "ENDPOINT"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"

	// Default variables names.
	defaultEndpoint  = "https://api.ultradns.com/"
	defaultUserAgent = "lego-provider-ultradns"
)

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *client.Client
}

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	Username           string        `yaml:"username"`
	Password           string        `yaml:"password"`
	Endpoint           string        `yaml:"endpoint"`
	TTL                int           `yaml:"ttl"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		Endpoint:           env.GetOrDefaultString(EnvEndpoint, defaultEndpoint),
		TTL:                env.GetOrDefaultInt(EnvTTL, 120),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, 2*time.Minute),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, 4*time.Second),
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		Endpoint:           defaultEndpoint,
		TTL:                120,
		PropagationTimeout: 2 * time.Minute,
		PollingInterval:    4 * time.Second,
	}
}

func GetYamlTemple() string {
	return `# Config 用于配置 DNSProvider 的创建。
username: "your_username"         # 用户名，用于身份验证
password: "your_password"         # 密码，与用户名配对用于身份验证
endpoint: "https://api.ultradns.com/" # API 端点的 URL，指向 DNS 提供者的 API
ttl: 120                          # DNS 记录的生存时间（秒），定义记录在缓存中存活的时间
propagationTimeout: 120s          # 传播超时时间，定义 DNS 记录传播的最长时间
pollingInterval: 4s               # 轮询间隔，定义检查 DNS 记录状态的时间间隔`
}

// NewDNSProvider returns a DNSProvider instance configured for ultradns.
// Credentials must be passed in the environment variables:
// ULTRADNS_USERNAME and ULTRADNS_PASSWORD.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvUsername, EnvPassword)
	if err != nil {
		return nil, fmt.Errorf("ultradns: %w", err)
	}

	config := NewDefaultConfig()
	config.Username = values[EnvUsername]
	config.Password = values[EnvPassword]

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

// NewDNSProviderConfig return a DNSProvider instance configured for ultradns.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("ultradns: the configuration of the DNS provider is nil")
	}

	ultraConfig := client.Config{
		Username:  config.Username,
		Password:  config.Password,
		HostURL:   config.Endpoint,
		UserAgent: defaultUserAgent,
	}

	uClient, err := client.NewClient(ultraConfig)
	if err != nil {
		return nil, fmt.Errorf("ultradns: %w", err)
	}

	return &DNSProvider{config: config, client: uClient}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// Present creates a TXT record using the specified parameters.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	authZone, err := dns01.FindZoneByFqdn(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("ultradns: could not find zone for domain %q: %w", domain, err)
	}

	recordService, err := record.Get(d.client)
	if err != nil {
		return fmt.Errorf("ultradns: %w", err)
	}

	rrSetKeyData := &rrset.RRSetKey{
		Owner:      info.EffectiveFQDN,
		Zone:       authZone,
		RecordType: "TXT",
	}

	res, _, _ := recordService.Read(rrSetKeyData)

	rrSetData := &rrset.RRSet{
		OwnerName: info.EffectiveFQDN,
		TTL:       d.config.TTL,
		RRType:    "TXT",
		RData:     []string{info.Value},
	}

	if res != nil && res.StatusCode == 200 {
		_, err = recordService.Update(rrSetKeyData, rrSetData)
	} else {
		_, err = recordService.Create(rrSetKeyData, rrSetData)
	}
	if err != nil {
		return fmt.Errorf("ultradns: %w", err)
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	authZone, err := dns01.FindZoneByFqdn(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("ultradns: could not find zone for domain %q: %w", domain, err)
	}

	recordService, err := record.Get(d.client)
	if err != nil {
		return fmt.Errorf("ultradns: %w", err)
	}

	rrSetKeyData := &rrset.RRSetKey{
		Owner:      info.EffectiveFQDN,
		Zone:       authZone,
		RecordType: "TXT",
	}

	_, err = recordService.Delete(rrSetKeyData)
	if err != nil {
		return fmt.Errorf("ultradns: %w", err)
	}

	return nil
}
