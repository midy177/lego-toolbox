// Package efficientip implements a DNS provider for solving the DNS-01 challenge using Efficient IP.
package efficientip

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"legotoolbox/providers/dns/efficientip/internal"
)

// Environment variables names.
const (
	envNamespace = "EFFICIENTIP_"

	EnvUsername = envNamespace + "USERNAME"
	EnvPassword = envNamespace + "PASSWORD"
	EnvHostname = envNamespace + "HOSTNAME"
	EnvDNSName  = envNamespace + "DNS_NAME"
	EnvViewName = envNamespace + "VIEW_NAME"

	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
	EnvInsecureSkipVerify = envNamespace + "INSECURE_SKIP_VERIFY"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	Username           string        `yaml:"username"`
	Password           string        `yaml:"password"`
	Hostname           string        `yaml:"hostname"`
	DNSName            string        `yaml:"dnsName"`
	ViewName           string        `yaml:"viewName"`
	InsecureSkipVerify bool          `yaml:"insecureSkipVerify"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	HTTPClient         *http.Client  `yaml:"-"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, dns01.DefaultPropagationTimeout),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, dns01.DefaultPollingInterval),
		HTTPClient: &http.Client{
			Timeout: env.GetOrDefaultSecond(EnvHTTPTimeout, 10*time.Second),
		},
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		PropagationTimeout: dns01.DefaultPropagationTimeout,
		PollingInterval:    dns01.DefaultPollingInterval,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func GetYamlTemple() string {
	return `# config.yaml
username: "your_username"          # 用户名，用于身份验证
password: "your_password"          # 密码，用于身份验证
hostname: "your_hostname"          # 主机名
dnsName: "your_dns_name"           # DNS 名称
viewName: "your_view_name"         # 视图名称
insecureSkipVerify: false          # 是否跳过 SSL 证书验证
propagationTimeout: 600s           # 传播超时时间，单位为秒
pollingInterval: 30s               # 轮询间隔时间，单位为秒`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *internal.Client
}

// NewDNSProvider returns a new DNS provider
// using environment variable EFFICIENTIP_API_KEY for adding and removing the DNS record.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvUsername, EnvPassword, EnvHostname, EnvDNSName)
	if err != nil {
		return nil, fmt.Errorf("efficientip: %w", err)
	}

	config := NewDefaultConfig()
	config.Username = values[EnvUsername]
	config.Password = values[EnvPassword]
	config.Hostname = values[EnvHostname]
	config.DNSName = values[EnvDNSName]
	config.ViewName = env.GetOrDefaultString(EnvViewName, "")
	config.InsecureSkipVerify = env.GetOrDefaultBool(EnvInsecureSkipVerify, false)

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

// NewDNSProviderConfig return a DNSProvider instance configured for Efficient IP.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("efficientip: the configuration of the DNS provider is nil")
	}

	if config.Username == "" {
		return nil, errors.New("efficientip: missing username")
	}
	if config.Password == "" {
		return nil, errors.New("efficientip: missing password")
	}
	if config.Hostname == "" {
		return nil, errors.New("efficientip: missing hostname")
	}
	if config.DNSName == "" {
		return nil, errors.New("efficientip: missing dnsname")
	}

	client := internal.NewClient(config.Hostname, config.Username, config.Password)

	if config.HTTPClient != nil {
		client.HTTPClient = config.HTTPClient
	}

	if config.InsecureSkipVerify {
		client.HTTPClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	return &DNSProvider{config: config, client: client}, nil
}

func (d *DNSProvider) Present(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	ctx := context.Background()

	r := internal.ResourceRecord{
		RRName:      dns01.UnFqdn(info.EffectiveFQDN),
		RRType:      "TXT",
		Value1:      info.Value,
		DNSName:     d.config.DNSName,
		DNSViewName: d.config.ViewName,
	}

	_, err := d.client.AddRecord(ctx, r)
	if err != nil {
		return fmt.Errorf("efficientip: add record: %w", err)
	}

	return nil
}

func (d *DNSProvider) CleanUp(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	ctx := context.Background()

	params := internal.DeleteInputParameters{
		RRName:      dns01.UnFqdn(info.EffectiveFQDN),
		RRType:      "TXT",
		RRValue1:    info.Value,
		DNSName:     d.config.DNSName,
		DNSViewName: d.config.ViewName,
	}

	_, err := d.client.DeleteRecord(ctx, params)
	if err != nil {
		return fmt.Errorf("efficientip: delete record: %w", err)
	}

	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}
