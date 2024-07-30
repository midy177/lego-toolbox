// Package versio implements a DNS provider for solving the DNS-01 challenge using versio DNS.
package versio

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"legotoolbox/providers/dns/versio/internal"
)

// Environment variables names.
const (
	envNamespace = "VERSIO_"

	EnvUsername = envNamespace + "USERNAME"
	EnvPassword = envNamespace + "PASSWORD"
	EnvEndpoint = envNamespace + "ENDPOINT"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvSequenceInterval   = envNamespace + "SEQUENCE_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	baseURL            *url.URL      `yaml:"-"`
	BaseURL            string        `yaml:"baseURL"`
	TTL                int           `yaml:"ttl"`
	Username           string        `yaml:"username"`
	Password           string        `yaml:"password"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	SequenceInterval   time.Duration `yaml:"sequenceInterval"`
	HTTPClient         *http.Client  `yaml:"-"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	baseURL, err := url.Parse(env.GetOrDefaultString(EnvEndpoint, internal.DefaultBaseURL))
	if err != nil {
		baseURL, _ = url.Parse(internal.DefaultBaseURL)
	}

	return &Config{
		baseURL:            baseURL,
		TTL:                env.GetOrDefaultInt(EnvTTL, 300),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, 60*time.Second),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, 5*time.Second),
		SequenceInterval:   env.GetOrDefaultSecond(EnvSequenceInterval, dns01.DefaultPropagationTimeout),
		HTTPClient: &http.Client{
			Timeout: env.GetOrDefaultSecond(EnvHTTPTimeout, 30*time.Second),
		},
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	baseURL, _ := url.Parse(internal.DefaultBaseURL)
	return &Config{
		baseURL:            baseURL,
		TTL:                300,
		PropagationTimeout: 60 * time.Second,
		PollingInterval:    5 * time.Second,
		SequenceInterval:   dns01.DefaultPropagationTimeout,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func GetYamlTemple() string {
	return `# Config 是用来配置 DNSProvider 的创建。
baseURL: "https://www.versio.nl/api/v1/"   # BaseURL，API 端点，用于与 DNS 服务提供商通信的 URL
ttl: 300                              # TTL，DNS 记录的生存时间（秒）
username: "your_username"             # 用户名，用于身份验证
password: "your_password"             # 密码，用于身份验证
propagationTimeout: 60s               # PropagationTimeout，传播超时时间，指定更新记录后等待传播的最大时间，单位为秒（s）
pollingInterval: 5s                   # PollingInterval，轮询间隔时间，指定系统检查 DNS 记录状态的频率，单位为秒（s）
sequenceInterval: 60s                 # SequenceInterval，顺序间隔时间，指定系统在处理连续请求时的间隔时间，单位为秒（s）`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *internal.Client

	dnsEntriesMu sync.Mutex
}

// NewDNSProvider returns a DNSProvider instance.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvUsername, EnvPassword)
	if err != nil {
		return nil, fmt.Errorf("versio: %w", err)
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
	if config.BaseURL != "" {
		config.baseURL, err = url.Parse(config.BaseURL)
		if err != nil {
			return nil, err
		}
	}
	return config, nil
}

// NewDNSProviderConfig return a DNSProvider instance configured for Versio.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("versio: the configuration of the DNS provider is nil")
	}
	if config.Username == "" {
		return nil, errors.New("versio: the versio username is missing")
	}
	if config.Password == "" {
		return nil, errors.New("versio: the versio password is missing")
	}

	client := internal.NewClient(config.Username, config.Password)

	if config.BaseURL != "" {
		client.BaseURL = config.baseURL
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

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	authZone, err := dns01.FindZoneByFqdn(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("versio: could not find zone for domain %q: %w", domain, err)
	}

	// use mutex to prevent race condition from getDNSRecords until postDNSRecords
	d.dnsEntriesMu.Lock()
	defer d.dnsEntriesMu.Unlock()

	ctx := context.Background()

	zoneName := dns01.UnFqdn(authZone)

	domains, err := d.client.GetDomain(ctx, zoneName)
	if err != nil {
		return fmt.Errorf("versio: %w", err)
	}

	txtRecord := internal.Record{
		Type:  "TXT",
		Name:  info.EffectiveFQDN,
		Value: `"` + info.Value + `"`,
		TTL:   d.config.TTL,
	}

	// Add new txtRecord to existing array of DNSRecords.
	// We'll need all the dns_records to add a new TXT record.
	msg := &domains.DomainInfo
	msg.DNSRecords = append(msg.DNSRecords, txtRecord)

	_, err = d.client.UpdateDomain(ctx, zoneName, msg)
	if err != nil {
		return fmt.Errorf("versio: %w", err)
	}
	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	authZone, err := dns01.FindZoneByFqdn(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("versio: could not find zone for domain %q: %w", domain, err)
	}

	// use mutex to prevent race condition from getDNSRecords until postDNSRecords
	d.dnsEntriesMu.Lock()
	defer d.dnsEntriesMu.Unlock()

	ctx := context.Background()

	zoneName := dns01.UnFqdn(authZone)

	domains, err := d.client.GetDomain(ctx, zoneName)
	if err != nil {
		return fmt.Errorf("versio: %w", err)
	}

	// loop through the existing entries and remove the specific record
	msg := &internal.DomainInfo{}
	for _, e := range domains.DomainInfo.DNSRecords {
		if e.Name != info.EffectiveFQDN {
			msg.DNSRecords = append(msg.DNSRecords, e)
		}
	}

	_, err = d.client.UpdateDomain(ctx, zoneName, msg)
	if err != nil {
		return fmt.Errorf("versio: %w", err)
	}
	return nil
}
