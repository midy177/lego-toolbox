// Package loopia implements a DNS provider for solving the DNS-01 challenge using loopia DNS.
package loopia

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
	"lego-toolbox/providers/dns/loopia/internal"
)

const minTTL = 300

// Environment variables names.
const (
	envNamespace = "LOOPIA_"

	EnvAPIUser     = envNamespace + "API_USER"
	EnvAPIPassword = envNamespace + "API_PASSWORD"
	EnvAPIURL      = envNamespace + "API_URL"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

type dnsClient interface {
	AddTXTRecord(ctx context.Context, domain string, subdomain string, ttl int, value string) error
	RemoveTXTRecord(ctx context.Context, domain string, subdomain string, recordID int) error
	GetTXTRecords(ctx context.Context, domain string, subdomain string) ([]internal.RecordObj, error)
	RemoveSubdomain(ctx context.Context, domain, subdomain string) error
}

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	BaseURL            string        `yaml:"baseURL"`
	APIUser            string        `yaml:"apiUser"`
	APIPassword        string        `yaml:"apiPassword"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	TTL                int           `yaml:"ttl"`
	HTTPClient         *http.Client  `yaml:"-"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt(EnvTTL, minTTL),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, 40*time.Minute),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, 60*time.Second),
		HTTPClient: &http.Client{
			Timeout: env.GetOrDefaultSecond(EnvHTTPTimeout, 60*time.Second),
		},
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		TTL:                minTTL,
		PropagationTimeout: 40 * time.Minute,
		PollingInterval:    60 * time.Second,
		HTTPClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func GetYamlTemple() string {
	return `# YAML 示例
baseURL: "https://api.loopia.se/RPCSERV"     # 基础 URL，用于 API 请求
apiUser: "your_api_user_here"                # API 用户名，用于身份验证
apiPassword: "your_api_password_here"        # API 密码，用于身份验证
propagationTimeout: 40m                      # 传播超时时间，表示系统等待变化传播的最长时间
pollingInterval: 60s                         # 轮询间隔时间，表示系统定期检查更新的时间间隔
ttl: 300                                     # TTL（Time to Live），表示数据或缓存的有效时间（以秒为单位）`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client dnsClient

	inProgressInfo map[string]int
	inProgressMu   sync.Mutex

	// only for testing purpose.
	findZoneByFqdn func(fqdn string) (string, error)
}

// NewDNSProvider returns a DNSProvider instance configured for Loopia.
// Credentials must be passed in the environment variables:
// LOOPIA_API_USER, LOOPIA_API_PASSWORD.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvAPIUser, EnvAPIPassword)
	if err != nil {
		return nil, fmt.Errorf("loopia: %w", err)
	}

	config := NewDefaultConfig()
	config.APIUser = values[EnvAPIUser]
	config.APIPassword = values[EnvAPIPassword]
	config.BaseURL = env.GetOrDefaultString(EnvAPIURL, internal.DefaultBaseURL)

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

// NewDNSProviderConfig return a DNSProvider instance configured for Loopia.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("loopia: the configuration of the DNS provider is nil")
	}

	if config.APIUser == "" || config.APIPassword == "" {
		return nil, errors.New("loopia: credentials missing")
	}

	// Min value for TTL is 300
	if config.TTL < 300 {
		config.TTL = 300
	}

	client := internal.NewClient(config.APIUser, config.APIPassword)

	if config.HTTPClient != nil {
		client.HTTPClient = config.HTTPClient
	}

	if config.BaseURL != "" {
		client.BaseURL = config.BaseURL
	}

	return &DNSProvider{
		config:         config,
		client:         client,
		findZoneByFqdn: dns01.FindZoneByFqdn,
		inProgressInfo: make(map[string]int),
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

	subDomain, authZone, err := d.splitDomain(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("loopia: %w", err)
	}

	ctx := context.Background()

	err = d.client.AddTXTRecord(ctx, authZone, subDomain, d.config.TTL, info.Value)
	if err != nil {
		return fmt.Errorf("loopia: failed to add TXT record: %w", err)
	}

	txtRecords, err := d.client.GetTXTRecords(ctx, authZone, subDomain)
	if err != nil {
		return fmt.Errorf("loopia: failed to get TXT records: %w", err)
	}

	d.inProgressMu.Lock()
	defer d.inProgressMu.Unlock()

	for _, r := range txtRecords {
		if r.Rdata == info.Value {
			d.inProgressInfo[token] = r.RecordID
			return nil
		}
	}

	return errors.New("loopia: failed to find the stored TXT record")
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	subDomain, authZone, err := d.splitDomain(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("loopia: %w", err)
	}

	d.inProgressMu.Lock()
	defer d.inProgressMu.Unlock()

	ctx := context.Background()

	err = d.client.RemoveTXTRecord(ctx, authZone, subDomain, d.inProgressInfo[token])
	if err != nil {
		return fmt.Errorf("loopia: failed to remove TXT record: %w", err)
	}

	records, err := d.client.GetTXTRecords(ctx, authZone, subDomain)
	if err != nil {
		return fmt.Errorf("loopia: failed to get TXT records: %w", err)
	}

	if len(records) > 0 {
		return nil
	}

	err = d.client.RemoveSubdomain(ctx, authZone, subDomain)
	if err != nil {
		return fmt.Errorf("loopia: failed to remove subdomain: %w", err)
	}

	return nil
}

func (d *DNSProvider) splitDomain(fqdn string) (string, string, error) {
	authZone, err := d.findZoneByFqdn(fqdn)
	if err != nil {
		return "", "", fmt.Errorf("could not find zone: %w", err)
	}

	subDomain, err := dns01.ExtractSubDomain(fqdn, authZone)
	if err != nil {
		return "", "", err
	}

	return subDomain, dns01.UnFqdn(authZone), nil
}
