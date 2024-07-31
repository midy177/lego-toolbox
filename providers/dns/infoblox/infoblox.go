// Package infoblox implements a DNS provider for solving the DNS-01 challenge using on prem infoblox DNS.
package infoblox

import (
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"strconv"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	infoblox "github.com/infobloxopen/infoblox-go-client"
)

// Environment variables names.
const (
	envNamespace = "INFOBLOX_"

	EnvHost        = envNamespace + "HOST"
	EnvPort        = envNamespace + "PORT"
	EnvUsername    = envNamespace + "USERNAME"
	EnvPassword    = envNamespace + "PASSWORD"
	EnvDNSView     = envNamespace + "DNS_VIEW"
	EnvWApiVersion = envNamespace + "WAPI_VERSION"
	EnvSSLVerify   = envNamespace + "SSL_VERIFY"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

const (
	defaultPoolConnections = 10
	defaultUserAgent       = "go-acme/lego"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	// Host is the URL of the grid manager.
	Host string `yaml:"host"`
	// Port is the Port for the grid manager.
	Port string `yaml:"port"`

	// Username the user for accessing API.
	Username string `yaml:"username"`
	// Password the password for accessing API.
	Password string `yaml:"password"`

	// DNSView is the dns view to put new records and search from.
	DNSView string `yaml:"dnsView"`
	// WapiVersion is the version of web api used.
	WapiVersion string `yaml:"wapiVersion"`

	// SSLVerify is whether or not to verify the ssl of the server being hit.
	SSLVerify bool `yaml:"sslVerify"`

	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	TTL                int           `yaml:"ttl"`
	HTTPTimeout        int           `yaml:"httpTimeout"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		DNSView:     env.GetOrDefaultString(EnvDNSView, "External"),
		WapiVersion: env.GetOrDefaultString(EnvWApiVersion, "2.11"),
		Port:        env.GetOrDefaultString(EnvPort, "443"),
		SSLVerify:   env.GetOrDefaultBool(EnvSSLVerify, true),

		TTL:                env.GetOrDefaultInt(EnvTTL, dns01.DefaultTTL),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, dns01.DefaultPropagationTimeout),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, dns01.DefaultPollingInterval),
		HTTPTimeout:        env.GetOrDefaultInt(EnvHTTPTimeout, 30),
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		DNSView:            "External",
		WapiVersion:        "2.11",
		Port:               "443",
		SSLVerify:          true,
		TTL:                dns01.DefaultTTL,
		PropagationTimeout: dns01.DefaultPropagationTimeout,
		PollingInterval:    dns01.DefaultPollingInterval,
		HTTPTimeout:        30,
	}
}

func GetYamlTemple() string {
	return `# 配置文件模板
# Grid管理器的URL
host: "your_grid_manager_url"
# Grid管理器的端口
port: "443"
# 访问API的用户名
username: "your_username"
# 访问API的密码
password: "your_password"
# DNS视图，用于放置新记录和搜索
dnsView: "External"
# 使用的Web API版本
wapiVersion: "2.11"
# 是否验证服务器的SSL
sslVerify: true
# 传播超时，设置一个时间段，例如：10s, 1m
propagationTimeout: "60s"
# 轮询间隔，设置一个时间段，例如：2s, 30s
pollingInterval: "2s"
# TTL (Time To Live)，设置一个整数值
ttl: 3600
# HTTP请求超时，设置一个整数值（以秒为单位）
httpTimeout: 30`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config          *Config
	transportConfig infoblox.TransportConfig
	ibConfig        infoblox.HostConfig

	recordRefs   map[string]string
	recordRefsMu sync.Mutex
}

// NewDNSProvider returns a DNSProvider instance configured for Infoblox.
// Credentials must be passed in the environment variables:
// INFOBLOX_USERNAME, INFOBLOX_PASSWORD
// INFOBLOX_HOST, INFOBLOX_PORT
// INFOBLOX_DNS_VIEW, INFOBLOX_WAPI_VERSION
// INFOBLOX_SSL_VERIFY.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvHost, EnvUsername, EnvPassword)
	if err != nil {
		return nil, fmt.Errorf("infoblox: %w", err)
	}

	config := NewDefaultConfig()
	config.Host = values[EnvHost]
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

// NewDNSProviderConfig return a DNSProvider instance configured for HyperOne.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("infoblox: the configuration of the DNS provider is nil")
	}

	if config.Host == "" {
		return nil, errors.New("infoblox: missing host")
	}

	if config.Username == "" || config.Password == "" {
		return nil, errors.New("infoblox: missing credentials")
	}

	return &DNSProvider{
		config:          config,
		transportConfig: infoblox.NewTransportConfig(strconv.FormatBool(config.SSLVerify), config.HTTPTimeout, defaultPoolConnections),
		ibConfig: infoblox.HostConfig{
			Host:     config.Host,
			Version:  config.WapiVersion,
			Port:     config.Port,
			Username: config.Username,
			Password: config.Password,
		},
		recordRefs: make(map[string]string),
	}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	connector, err := infoblox.NewConnector(d.ibConfig, d.transportConfig, &infoblox.WapiRequestBuilder{}, &infoblox.WapiHttpRequestor{})
	if err != nil {
		return fmt.Errorf("infoblox: %w", err)
	}

	defer func() { _ = connector.Logout() }()

	objectManager := infoblox.NewObjectManager(connector, defaultUserAgent, "")

	record, err := objectManager.CreateTXTRecord(dns01.UnFqdn(info.EffectiveFQDN), info.Value, uint(d.config.TTL), d.config.DNSView)
	if err != nil {
		return fmt.Errorf("infoblox: could not create TXT record for %s: %w", domain, err)
	}

	d.recordRefsMu.Lock()
	d.recordRefs[token] = record.Ref
	d.recordRefsMu.Unlock()

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	connector, err := infoblox.NewConnector(d.ibConfig, d.transportConfig, &infoblox.WapiRequestBuilder{}, &infoblox.WapiHttpRequestor{})
	if err != nil {
		return fmt.Errorf("infoblox: %w", err)
	}

	defer func() { _ = connector.Logout() }()

	objectManager := infoblox.NewObjectManager(connector, defaultUserAgent, "")

	// gets the record's unique ref from when we created it
	d.recordRefsMu.Lock()
	recordRef, ok := d.recordRefs[token]
	d.recordRefsMu.Unlock()
	if !ok {
		return fmt.Errorf("infoblox: unknown record ID for '%s' '%s'", info.EffectiveFQDN, token)
	}

	_, err = objectManager.DeleteTXTRecord(recordRef)
	if err != nil {
		return fmt.Errorf("infoblox: could not delete TXT record for %s: %w", domain, err)
	}

	// Delete record ref from map
	d.recordRefsMu.Lock()
	delete(d.recordRefs, token)
	d.recordRefsMu.Unlock()

	return nil
}
