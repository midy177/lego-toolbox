// Package sonic implements a DNS provider for solving the DNS-01 challenge using  Sonic.
package sonic

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"lego-toolbox/providers/dns/sonic/internal"
)

// Environment variables names.
const (
	envNamespace = "SONIC_"

	EnvUserID = envNamespace + "USER_ID"
	EnvAPIKey = envNamespace + "API_KEY"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvSequenceInterval   = envNamespace + "SEQUENCE_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	UserID             string        `yaml:"userID"`
	APIKey             string        `yaml:"apiKey"`
	HTTPClient         *http.Client  `yaml:"-"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	SequenceInterval   time.Duration `yaml:"sequenceInterval"`
	TTL                int           `yaml:"ttl"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt(EnvTTL, dns01.DefaultTTL),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, dns01.DefaultPropagationTimeout),
		SequenceInterval:   env.GetOrDefaultSecond(EnvSequenceInterval, dns01.DefaultPropagationTimeout),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, dns01.DefaultPollingInterval),
		HTTPClient: &http.Client{
			Timeout: env.GetOrDefaultSecond(EnvHTTPTimeout, 10*time.Second),
		},
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		TTL:                dns01.DefaultTTL,
		PropagationTimeout: dns01.DefaultPropagationTimeout,
		SequenceInterval:   dns01.DefaultPropagationTimeout,
		PollingInterval:    dns01.DefaultPollingInterval,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func GetYamlTemple() string {
	return `# YAML 示例
userID: "your_user_id_here"                   # 用户 ID，用于标识用户
apiKey: "your_api_key_here"                   # API 密钥，用于身份验证和授权
propagationTimeout: 60s                       # 传播超时时间，表示系统等待变化传播的最长时间
pollingInterval: 60s                          # 轮询间隔时间，表示系统定期检查更新的时间间隔
sequenceInterval: 2s                         # 序列间隔时间
ttl: 120                                      # TTL（Time to Live），表示数据或缓存的有效时间（以秒为单位）`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *internal.Client
}

// NewDNSProvider returns a DNSProvider instance configured for Sonic.
// Credentials must be passed in the environment variables:
// SONIC_USERID and SONIC_APIKEY.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvUserID, EnvAPIKey)
	if err != nil {
		return nil, fmt.Errorf("sonic: %w", err)
	}

	config := NewDefaultConfig()
	config.UserID = values[EnvUserID]
	config.APIKey = values[EnvAPIKey]

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

// NewDNSProviderConfig return a DNSProvider instance configured for Sonic.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("sonic: the configuration of the DNS provider is nil")
	}

	client, err := internal.NewClient(config.UserID, config.APIKey)
	if err != nil {
		return nil, fmt.Errorf("sonic: %w", err)
	}

	if config.HTTPClient != nil {
		client.HTTPClient = config.HTTPClient
	}

	return &DNSProvider{client: client, config: config}, nil
}

// Present creates a TXT record using the specified parameters.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	err := d.client.SetRecord(context.Background(), dns01.UnFqdn(info.EffectiveFQDN), info.Value, d.config.TTL)
	if err != nil {
		return fmt.Errorf("sonic: unable to create record for %s: %w", info.EffectiveFQDN, err)
	}

	return nil
}

// CleanUp removes the TXT records matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	err := d.client.SetRecord(context.Background(), dns01.UnFqdn(info.EffectiveFQDN), "_", d.config.TTL)
	if err != nil {
		return fmt.Errorf("sonic: unable to clean record for %s: %w", info.EffectiveFQDN, err)
	}

	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// Sequential All DNS challenges for this provider will be resolved sequentially.
// Returns the interval between each iteration.
func (d *DNSProvider) Sequential() time.Duration {
	return d.config.SequenceInterval
}
