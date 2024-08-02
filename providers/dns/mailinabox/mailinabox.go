// Package mailinabox implements a DNS provider for solving the DNS-01 challenge using Mail-in-a-Box.
package mailinabox

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/nrdcg/mailinabox"
)

// Environment variables names.
const (
	envNamespace = "MAILINABOX_"

	EnvEmail    = envNamespace + "EMAIL"
	EnvPassword = envNamespace + "PASSWORD"
	EnvBaseURL  = envNamespace + "BASE_URL"

	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	Email              string        `yaml:"email"`
	Password           string        `yaml:"password"`
	BaseURL            string        `yaml:"baseURL"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, 120*time.Second),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, 4*time.Second),
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		PropagationTimeout: 120 * time.Second,
		PollingInterval:    4 * time.Second,
	}
}

func GetYamlTemple() string {
	return `# YAML 示例
email: "your_email@example.com"               # 电子邮件地址，用于身份验证或通知
password: "your_password_here"                # 密码，用于身份验证
baseURL: "https://api.example.com"            # 基础 URL，用于 API 请求
propagationTimeout: 120s                      # 传播超时时间，表示系统等待变化传播的最长时间
pollingInterval: 4s                           # 轮询间隔时间，表示系统定期检查更新的时间间隔`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *mailinabox.Client
}

// NewDNSProvider returns a DNSProvider instance configured for Mail-in-a-Box.
// Credentials must be passed in the environment variables:
// MAILINABOX_EMAIL, MAILINABOX_PASSWORD, and MAILINABOX_BASE_URL.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvBaseURL, EnvEmail, EnvPassword)
	if err != nil {
		return nil, fmt.Errorf("mailinabox: %w", err)
	}

	config := NewDefaultConfig()
	config.BaseURL = values[EnvBaseURL]
	config.Email = values[EnvEmail]
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

// NewDNSProviderConfig return a DNSProvider instance configured for deSEC.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("mailinabox: the configuration of the DNS provider is nil")
	}

	if config.Email == "" || config.Password == "" {
		return nil, errors.New("mailinabox: incomplete credentials, missing email or password")
	}

	if config.BaseURL == "" {
		return nil, errors.New("mailinabox: missing base URL")
	}

	client, err := mailinabox.New(config.BaseURL, config.Email, config.Password)
	if err != nil {
		return nil, fmt.Errorf("mailinabox: %w", err)
	}

	return &DNSProvider{config: config, client: client}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// Present creates a TXT record using the specified parameters.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	ctx := context.Background()
	info := dns01.GetChallengeInfo(domain, keyAuth)

	record := mailinabox.Record{
		Name:  dns01.UnFqdn(info.EffectiveFQDN),
		Type:  "TXT",
		Value: info.Value,
	}

	_, err := d.client.DNS.AddRecord(ctx, record)
	if err != nil {
		return fmt.Errorf("mailinabox: add record: %w", err)
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	ctx := context.Background()
	info := dns01.GetChallengeInfo(domain, keyAuth)

	record := mailinabox.Record{
		Name:  dns01.UnFqdn(info.EffectiveFQDN),
		Type:  "TXT",
		Value: info.Value,
	}

	_, err := d.client.DNS.RemoveRecord(ctx, record)
	if err != nil {
		return fmt.Errorf("mailinabox: remove record: %w", err)
	}

	return nil
}
