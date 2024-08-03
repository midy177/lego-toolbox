// Package variomedia implements a DNS provider for solving the DNS-01 challenge using Variomedia DNS.
package variomedia

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/go-acme/lego/v4/platform/wait"
	"lego-toolbox/providers/dns/variomedia/internal"
)

// Environment variables names.
const (
	envNamespace = "VARIOMEDIA_"

	EnvAPIToken = envNamespace + "API_TOKEN"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvSequenceInterval   = envNamespace + "SEQUENCE_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	APIToken           string        `yaml:"apiToken"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	SequenceInterval   time.Duration `yaml:"sequenceInterval"`
	TTL                int           `yaml:"ttl"`
	HTTPClient         *http.Client  `yaml:"-"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt(EnvTTL, 300),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, dns01.DefaultPropagationTimeout),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, dns01.DefaultPollingInterval),
		SequenceInterval:   env.GetOrDefaultSecond(EnvSequenceInterval, dns01.DefaultPropagationTimeout),
		HTTPClient: &http.Client{
			Timeout: env.GetOrDefaultSecond(EnvHTTPTimeout, 30*time.Second),
		},
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		TTL:                300,
		PropagationTimeout: dns01.DefaultPropagationTimeout,
		PollingInterval:    dns01.DefaultPollingInterval,
		SequenceInterval:   dns01.DefaultPropagationTimeout,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func GetYamlTemple() string {
	return `# Config 用于配置 DNSProvider 的创建。
apiToken: "your_api_token"  # API 访问令牌
propagationTimeout: 60s     # 传播超时时间，定义 DNS 记录传播的最长时间
pollingInterval: 2s         # 轮询间隔，定义检查 DNS 记录状态的时间间隔
sequenceInterval: 60s       # 序列间隔，定义每次操作之间的最小时间间隔
ttl: 300                    # DNS 记录的生存时间（秒）`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *internal.Client

	recordIDs   map[string]string
	recordIDsMu sync.Mutex
}

// NewDNSProvider returns a DNSProvider instance.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvAPIToken)
	if err != nil {
		return nil, fmt.Errorf("variomedia: %w", err)
	}

	config := NewDefaultConfig()
	config.APIToken = values[EnvAPIToken]

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

// NewDNSProviderConfig return a DNSProvider instance configured for Variomedia.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config.APIToken == "" {
		return nil, errors.New("variomedia: missing credentials")
	}

	client := internal.NewClient(config.APIToken)

	if config.HTTPClient != nil {
		client.HTTPClient = config.HTTPClient
	}

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

// Sequential All DNS challenges for this provider will be resolved sequentially.
// Returns the interval between each iteration.
func (d *DNSProvider) Sequential() time.Duration {
	return d.config.SequenceInterval
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	authZone, err := dns01.FindZoneByFqdn(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("variomedia: could not find zone for domain %q: %w", domain, err)
	}

	subDomain, err := dns01.ExtractSubDomain(info.EffectiveFQDN, authZone)
	if err != nil {
		return fmt.Errorf("variomedia: %w", err)
	}

	ctx := context.Background()

	record := internal.DNSRecord{
		RecordType: "TXT",
		Name:       subDomain,
		Domain:     dns01.UnFqdn(authZone),
		Data:       info.Value,
		TTL:        d.config.TTL,
	}

	cdrr, err := d.client.CreateDNSRecord(ctx, record)
	if err != nil {
		return fmt.Errorf("variomedia: %w", err)
	}

	err = d.waitJob(ctx, domain, cdrr.Data.ID)
	if err != nil {
		return fmt.Errorf("variomedia: %w", err)
	}

	d.recordIDsMu.Lock()
	d.recordIDs[token] = strings.TrimPrefix(cdrr.Data.Links.DNSRecord, "https://api.variomedia.de/dns-records/")
	d.recordIDsMu.Unlock()

	return nil
}

// CleanUp removes the TXT record previously created.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	ctx := context.Background()

	// get the record's unique ID from when we created it
	d.recordIDsMu.Lock()
	recordID, ok := d.recordIDs[token]
	d.recordIDsMu.Unlock()
	if !ok {
		return fmt.Errorf("variomedia: unknown record ID for '%s'", info.EffectiveFQDN)
	}

	ddrr, err := d.client.DeleteDNSRecord(ctx, recordID)
	if err != nil {
		return fmt.Errorf("variomedia: %w", err)
	}

	err = d.waitJob(ctx, domain, ddrr.Data.ID)
	if err != nil {
		return fmt.Errorf("variomedia: %w", err)
	}

	return nil
}

func (d *DNSProvider) waitJob(ctx context.Context, domain string, id string) error {
	return wait.For("variomedia: apply change on "+domain, d.config.PropagationTimeout, d.config.PollingInterval, func() (bool, error) {
		result, err := d.client.GetJob(ctx, id)
		if err != nil {
			return false, err
		}

		log.Infof("variomedia: [%s] %s: %s %s", domain, result.Data.ID, result.Data.Attributes.JobType, result.Data.Attributes.Status)

		return result.Data.Attributes.Status == "done", nil
	})
}
