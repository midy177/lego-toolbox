// Package ibmcloud implements a DNS provider for solving the DNS-01 challenge using IBM Cloud (SoftLayer).
package ibmcloud

import (
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/softlayer/softlayer-go/session"
	"lego-toolbox/providers/dns/ibmcloud/internal"
)

// Environment variables names.
const (
	envNamespace = "SOFTLAYER_"

	// EnvUsername  the name must be the same as here:
	// https://github.com/softlayer/softlayer-go/blob/534185047ea683dd1e29fd23e445598295d94be4/session/session.go#L171
	EnvUsername = envNamespace + "USERNAME"
	// EnvAPIKey  the name must be the same as here:
	// https://github.com/softlayer/softlayer-go/blob/534185047ea683dd1e29fd23e445598295d94be4/session/session.go#L175
	EnvAPIKey = envNamespace + "API_KEY"
	// EnvHTTPTimeout the name must be the same as here:
	// https://github.com/softlayer/softlayer-go/blob/534185047ea683dd1e29fd23e445598295d94be4/session/session.go#L182
	EnvHTTPTimeout = envNamespace + "TIMEOUT"
	EnvDebug       = envNamespace + "DEBUG"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	Username           string        `yaml:"username"`
	APIKey             string        `yaml:"apiKey"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	TTL                int           `yaml:"ttl"`
	HTTPTimeout        time.Duration `yaml:"httpTimeout"`
	Debug              bool          `yaml:"-"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt(EnvTTL, dns01.DefaultTTL),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, dns01.DefaultPropagationTimeout),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, dns01.DefaultPollingInterval),
		HTTPTimeout:        env.GetOrDefaultSecond(EnvHTTPTimeout, session.DefaultTimeout),
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		TTL:                dns01.DefaultTTL,
		PropagationTimeout: dns01.DefaultPropagationTimeout,
		PollingInterval:    dns01.DefaultPollingInterval,
		HTTPTimeout:        session.DefaultTimeout,
	}
}

func GetYamlTemple() string {
	return `# 配置文件模板
# 用户名，用于身份验证
username: "your_username"
# API密钥，用于访问API
apiKey: "your_api_key"
# 传播超时，设置一个时间段，例如：10s, 1m
propagationTimeout: "60s"
# 轮询间隔，设置一个时间段，例如：5s, 30s
pollingInterval: "2s"
# TTL (Time To Live)，设置一个整数值
ttl: 120
# HTTP请求超时，设置一个时间段，例如：30s, 1m
httpTimeout: "120s"`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config  *Config
	wrapper *internal.Wrapper
}

// NewDNSProvider returns a DNSProvider instance configured for IBM Cloud (SoftLayer).
// Credentials must be passed in the environment variables:
// SOFTLAYER_USERNAME, SOFTLAYER_API_KEY.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvUsername, EnvAPIKey)
	if err != nil {
		return nil, fmt.Errorf("ibmcloud: %w", err)
	}

	config := NewDefaultConfig()
	config.Username = values[EnvUsername]
	config.APIKey = values[EnvAPIKey]
	config.Debug = env.GetOrDefaultBool(EnvDebug, false)

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

// NewDNSProviderConfig return a DNSProvider instance configured for IBM Cloud (SoftLayer).
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("ibmcloud: the configuration of the DNS provider is nil")
	}

	if config.Username == "" {
		return nil, errors.New("ibmcloud: username is missing")
	}

	if config.APIKey == "" {
		return nil, errors.New("ibmcloud: API key is missing")
	}

	sess := session.New(config.Username, config.APIKey)

	sess.Timeout = config.HTTPTimeout
	sess.Debug = config.Debug

	return &DNSProvider{wrapper: internal.NewWrapper(sess), config: config}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	// TODO(ldez) replace domain by FQDN to follow CNAME.
	err := d.wrapper.AddTXTRecord(info.EffectiveFQDN, domain, info.Value, d.config.TTL)
	if err != nil {
		return fmt.Errorf("ibmcloud: %w", err)
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	// TODO(ldez) replace domain by FQDN to follow CNAME.
	err := d.wrapper.CleanupTXTRecord(info.EffectiveFQDN, domain)
	if err != nil {
		return fmt.Errorf("ibmcloud: %w", err)
	}

	return nil
}
