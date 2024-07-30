// Package vercel implements a DNS provider for solving the DNS-01 challenge using Vercel DNS.
package vercel

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
	"legotoolbox/providers/dns/vercel/internal"
)

// Environment variables names.
const (
	envNamespace = "VERCEL_"

	EnvAuthToken = envNamespace + "API_TOKEN"
	EnvTeamID    = envNamespace + "TEAM_ID"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	AuthToken          string        `yaml:"authToken"`
	TeamID             string        `yaml:"teamID"`
	TTL                int           `yaml:"ttl"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	HTTPClient         *http.Client  `yaml:"-"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt(EnvTTL, 60),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, 60*time.Second),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, 5*time.Second),
		HTTPClient: &http.Client{
			Timeout: env.GetOrDefaultSecond(EnvHTTPTimeout, 30*time.Second),
		},
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		TTL:                60,
		PropagationTimeout: 60 * time.Second,
		PollingInterval:    5 * time.Second,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func GetYamlTemple() string {
	return `# Config 是用来配置 DNSProvider 的创建。
authToken: "your_auth_token"          # AuthToken，身份验证令牌，用于 API 访问
teamID: "your_team_id"                # TeamID，团队 ID，用于指定团队的唯一标识符
ttl: 60                               # TTL，DNS 记录的生存时间（秒）
propagationTimeout: 60s               # PropagationTimeout，传播超时时间，指定更新记录后等待传播的最大时间，单位为秒（s）
pollingInterval: 5s                   # PollingInterval，轮询间隔时间，指定系统检查 DNS 记录状态的频率，单位为秒（s）`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *internal.Client

	recordIDs   map[string]string
	recordIDsMu sync.Mutex
}

// NewDNSProvider returns a DNSProvider instance configured for Vercel.
// Credentials must be passed in the environment variables: VERCEL_API_TOKEN, VERCEL_TEAM_ID.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvAuthToken)
	if err != nil {
		return nil, fmt.Errorf("vercel: %w", err)
	}

	config := NewDefaultConfig()
	config.AuthToken = values[EnvAuthToken]
	config.TeamID = env.GetOrDefaultString(EnvTeamID, "")

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

// NewDNSProviderConfig return a DNSProvider instance configured for Digital Ocean.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("vercel: the configuration of the DNS provider is nil")
	}

	if config.AuthToken == "" {
		return nil, errors.New("vercel: credentials missing")
	}

	client := internal.NewClient(internal.OAuthStaticAccessToken(config.HTTPClient, config.AuthToken), config.TeamID)

	return &DNSProvider{
		config:    config,
		client:    client,
		recordIDs: make(map[string]string),
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
		return fmt.Errorf("vercel: could not find zone for domain %q: %w", domain, err)
	}

	record := internal.Record{
		Name:  info.EffectiveFQDN,
		Type:  "TXT",
		Value: info.Value,
		TTL:   d.config.TTL,
	}

	respData, err := d.client.CreateRecord(context.Background(), authZone, record)
	if err != nil {
		return fmt.Errorf("vercel: %w", err)
	}

	d.recordIDsMu.Lock()
	d.recordIDs[token] = respData.UID
	d.recordIDsMu.Unlock()

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	authZone, err := dns01.FindZoneByFqdn(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("vercel: could not find zone for domain %q: %w", domain, err)
	}

	// get the record's unique ID from when we created it
	d.recordIDsMu.Lock()
	recordID, ok := d.recordIDs[token]
	d.recordIDsMu.Unlock()
	if !ok {
		return fmt.Errorf("vercel: unknown record ID for '%s'", info.EffectiveFQDN)
	}

	err = d.client.DeleteRecord(context.Background(), authZone, recordID)
	if err != nil {
		return fmt.Errorf("vercel: %w", err)
	}

	// Delete record ID from map
	d.recordIDsMu.Lock()
	delete(d.recordIDs, token)
	d.recordIDsMu.Unlock()

	return nil
}
