// Package linode implements a DNS provider for solving the DNS-01 challenge using Linode DNS and Linode's APIv4
package linode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/linode/linodego"
	"golang.org/x/oauth2"
)

const (
	minTTL             = 300
	dnsUpdateFreqMins  = 15
	dnsUpdateFudgeSecs = 120
)

// Environment variables names.
const (
	envNamespace = "LINODE_"

	EnvToken = envNamespace + "TOKEN"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	Token              string        `yaml:"token"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	TTL                int           `yaml:"ttl"`
	HTTPTimeout        time.Duration `yaml:"httpTimeout"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt(EnvTTL, minTTL),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, 0),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, 15*time.Second),
		HTTPTimeout:        env.GetOrDefaultSecond(EnvHTTPTimeout, 0),
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		TTL:                minTTL,
		PropagationTimeout: 60 * time.Second,
		PollingInterval:    15 * time.Second,
		HTTPTimeout:        30,
	}
}

func GetYamlTemple() string {
	return `# YAML 示例
token: "your_token_here"              # 令牌，用于身份验证和授权
propagationTimeout: 60s               # 传播超时时间，表示系统等待变化传播的最长时间
pollingInterval: 15s                  # 轮询间隔时间，表示系统定期检查更新的时间间隔
ttl: 3600                             # TTL（Time to Live），表示数据或缓存的有效时间（以秒为单位）
httpTimeout: 30s                      # HTTP 超时时间，表示 HTTP 请求的最大持续时间`
}

type hostedZoneInfo struct {
	domainID     int
	resourceName string
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *linodego.Client
}

// NewDNSProvider returns a DNSProvider instance configured for Linode.
// Credentials must be passed in the environment variable: LINODE_TOKEN.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvToken)
	if err != nil {
		return nil, fmt.Errorf("linode: %w", err)
	}

	config := NewDefaultConfig()
	config.Token = values[EnvToken]

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

// NewDNSProviderConfig return a DNSProvider instance configured for Linode.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("linode: the configuration of the DNS provider is nil")
	}

	if config.Token == "" {
		return nil, errors.New("linode: Linode Access Token missing")
	}

	if config.TTL < minTTL {
		return nil, fmt.Errorf("linode: invalid TTL, TTL (%d) must be greater than %d", config.TTL, minTTL)
	}

	oauth2Client := &http.Client{
		Timeout: config.HTTPTimeout,
		Transport: &oauth2.Transport{
			Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: config.Token}),
		},
	}

	client := linodego.NewClient(oauth2Client)
	client.SetUserAgent("go-acme/lego https://github.com/linode/linodego")

	return &DNSProvider{config: config, client: &client}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (time.Duration, time.Duration) {
	timeout := d.config.PropagationTimeout
	if d.config.PropagationTimeout <= 0 {
		// Since Linode only updates their zone files every X minutes, we need
		// to figure out how many minutes we have to wait until we hit the next
		// interval of X.  We then wait another couple of minutes, just to be
		// safe.  Hopefully at some point during all of this, the record will
		// have propagated throughout Linode's network.
		minsRemaining := dnsUpdateFreqMins - (time.Now().Minute() % dnsUpdateFreqMins)

		timeout = (time.Duration(minsRemaining) * time.Minute) +
			(minTTL * time.Second) +
			(dnsUpdateFudgeSecs * time.Second)
	}

	return timeout, d.config.PollingInterval
}

// Present creates a TXT record using the specified parameters.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	zone, err := d.getHostedZoneInfo(info.EffectiveFQDN)
	if err != nil {
		return err
	}

	createOpts := linodego.DomainRecordCreateOptions{
		Name:   dns01.UnFqdn(info.EffectiveFQDN),
		Target: info.Value,
		TTLSec: d.config.TTL,
		Type:   linodego.RecordTypeTXT,
	}

	_, err = d.client.CreateDomainRecord(context.Background(), zone.domainID, createOpts)
	return err
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	zone, err := d.getHostedZoneInfo(info.EffectiveFQDN)
	if err != nil {
		return err
	}

	// Get all TXT records for the specified domain.
	listOpts := linodego.NewListOptions(0, `{"type":"TXT"}`)
	resources, err := d.client.ListDomainRecords(context.Background(), zone.domainID, listOpts)
	if err != nil {
		return err
	}

	// Remove the specified resource, if it exists.
	for _, resource := range resources {
		if (resource.Name == dns01.UnFqdn(info.EffectiveFQDN) || resource.Name == zone.resourceName) &&
			resource.Target == info.Value {
			if err := d.client.DeleteDomainRecord(context.Background(), zone.domainID, resource.ID); err != nil {
				return err
			}
		}
	}

	return nil
}

func (d *DNSProvider) getHostedZoneInfo(fqdn string) (*hostedZoneInfo, error) {
	// Lookup the zone that handles the specified FQDN.
	authZone, err := dns01.FindZoneByFqdn(fqdn)
	if err != nil {
		return nil, fmt.Errorf("could not find zone: %w", err)
	}

	// Query the authority zone.
	filter, err := json.Marshal(map[string]string{"domain": dns01.UnFqdn(authZone)})
	if err != nil {
		return nil, fmt.Errorf("failed to create JSON filter: %w", err)
	}

	listOpts := linodego.NewListOptions(0, string(filter))
	domains, err := d.client.ListDomains(context.Background(), listOpts)
	if err != nil {
		return nil, err
	}

	if len(domains) == 0 {
		return nil, errors.New("domain not found")
	}

	subDomain, err := dns01.ExtractSubDomain(fqdn, authZone)
	if err != nil {
		return nil, err
	}

	return &hostedZoneInfo{
		domainID:     domains[0].ID,
		resourceName: subDomain,
	}, nil
}
