// Package iijdpf implements a DNS provider for solving the DNS-01 challenge using IIJ DNS Platform Service.
package iijdpf

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/miekg/dns"
	dpfapi "github.com/mimuret/golang-iij-dpf/pkg/api"
	dpfapiutils "github.com/mimuret/golang-iij-dpf/pkg/apiutils"
)

// Environment variables names.
const (
	envNamespace = "IIJ_DPF_"

	EnvAPIToken    = envNamespace + "API_TOKEN"
	EnvServiceCode = envNamespace + "DPM_SERVICE_CODE"

	EnvAPIEndpoint        = envNamespace + "API_ENDPOINT"
	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	Token              string        `yaml:"token"`
	ServiceCode        string        `yaml:"serviceCode"`
	Endpoint           string        `yaml:"endpoint"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	TTL                int           `yaml:"ttl"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		Endpoint:           env.GetOrDefaultString(EnvAPIEndpoint, dpfapi.DefaultEndpoint),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, 660*time.Second),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, 5*time.Second),
		TTL:                env.GetOrDefaultInt(EnvTTL, 300),
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		Endpoint:           dpfapi.DefaultEndpoint,
		PropagationTimeout: 660 * time.Second,
		PollingInterval:    5 * time.Second,
		TTL:                300,
	}
}

func GetYamlTemple() string {
	return `# 配置文件模板
# 访问令牌，用于身份验证
token: "your_token"
# 服务代码，用于特定的服务操作
serviceCode: "your_service_code"
# 服务端点，API的访问URL
endpoint: "your_endpoint_url"
# 传播超时，设置一个时间段，例如：10s, 1m
propagationTimeout: "11m"
# 轮询间隔，设置一个时间段，例如：5s, 30s
pollingInterval: "5s"
# TTL (Time To Live)，设置一个整数值
ttl: 300`
}

var _ challenge.Provider = &DNSProvider{}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	client dpfapi.ClientInterface
	config *Config
}

// NewDNSProvider returns a DNSProvider instance configured for IIJ DNS.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvAPIToken, EnvServiceCode)
	if err != nil {
		return nil, fmt.Errorf("iijdpf: %w", err)
	}

	config := NewDefaultConfig()
	config.Token = values[EnvAPIToken]
	config.ServiceCode = values[EnvServiceCode]

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

// NewDNSProviderConfig takes a given config
// and returns a custom configured DNSProvider instance.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config.Token == "" {
		return nil, errors.New("iijdpf: API token missing")
	}

	if config.ServiceCode == "" {
		return nil, errors.New("iijdpf: Servicecode missing")
	}

	return &DNSProvider{
		client: dpfapi.NewClient(config.Token, config.Endpoint, nil),
		config: config,
	}, nil
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

	zoneID, err := dpfapiutils.GetZoneIdFromServiceCode(ctx, d.client, d.config.ServiceCode)
	if err != nil {
		return fmt.Errorf("iijdpf: failed to get zone id: %w", err)
	}

	err = d.addTxtRecord(ctx, zoneID, dns.CanonicalName(info.EffectiveFQDN), `"`+info.Value+`"`)
	if err != nil {
		return fmt.Errorf("iijdpf: %w", err)
	}

	err = d.commit(ctx, zoneID)
	if err != nil {
		return fmt.Errorf("iijdpf: %w", err)
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	ctx := context.Background()

	info := dns01.GetChallengeInfo(domain, keyAuth)

	zoneID, err := dpfapiutils.GetZoneIdFromServiceCode(ctx, d.client, d.config.ServiceCode)
	if err != nil {
		return fmt.Errorf("iijdpf: failed to get zone id: %w", err)
	}

	err = d.deleteTxtRecord(ctx, zoneID, dns.CanonicalName(info.EffectiveFQDN), `"`+info.Value+`"`)
	if err != nil {
		return fmt.Errorf("iijdpf: %w", err)
	}

	err = d.commit(ctx, zoneID)
	if err != nil {
		return fmt.Errorf("iijdpf: %w", err)
	}

	return nil
}
