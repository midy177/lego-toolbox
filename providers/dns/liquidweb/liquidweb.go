// Package liquidweb implements a DNS provider for solving the DNS-01 challenge using Liquid Web.
package liquidweb

import (
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	lw "github.com/liquidweb/liquidweb-go/client"
	"github.com/liquidweb/liquidweb-go/network"
)

const defaultBaseURL = "https://api.liquidweb.com"

// Environment variables names.
const (
	envNamespace    = "LIQUID_WEB_"
	altEnvNamespace = "LWAPI_"

	EnvURL      = envNamespace + "URL"
	EnvUsername = envNamespace + "USERNAME"
	EnvPassword = envNamespace + "PASSWORD"
	EnvZone     = envNamespace + "ZONE"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	BaseURL            string        `yaml:"baseURL"`
	Username           string        `yaml:"username"`
	Password           string        `yaml:"password"`
	Zone               string        `yaml:"zone"`
	TTL                int           `yaml:"ttl"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	HTTPTimeout        time.Duration `yaml:"httpTimeout"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		BaseURL:            defaultBaseURL,
		TTL:                env.GetOneWithFallback(EnvTTL, 300, strconv.Atoi, altEnvName(EnvTTL)),
		PropagationTimeout: env.GetOneWithFallback(EnvPropagationTimeout, 2*time.Minute, env.ParseSecond, altEnvName(EnvPropagationTimeout)),
		PollingInterval:    env.GetOneWithFallback(EnvPollingInterval, 2*time.Second, env.ParseSecond, altEnvName(EnvPollingInterval)),
		HTTPTimeout:        env.GetOneWithFallback(EnvHTTPTimeout, 1*time.Minute, env.ParseSecond, altEnvName(EnvHTTPTimeout)),
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		BaseURL:            defaultBaseURL,
		TTL:                300,
		PropagationTimeout: 2 * time.Minute,
		PollingInterval:    2 * time.Second,
		HTTPTimeout:        1 * time.Minute,
	}
}

func GetYamlTemple() string {
	return `# YAML 示例
baseURL: "https://api.liquidweb.com"         # 基础 URL，用于 API 请求
username: "your_username_here"               # 用户名，用于身份验证
password: "your_password_here"               # 密码，用于身份验证
zone: "example.com"                          # 域名区域，用于 DNS 配置
ttl: 300                                     # TTL（Time to Live），表示数据或缓存的有效时间（以秒为单位）
pollingInterval: 2s                          # 轮询间隔时间，表示系统定期检查更新的时间间隔
propagationTimeout: 120s                     # 传播超时时间，表示系统等待变化传播的最长时间
httpTimeout: 60s                             # HTTP 超时时间，表示 HTTP 请求的超时时间`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config      *Config
	client      *lw.API
	recordIDs   map[string]int
	recordIDsMu sync.Mutex
}

// NewDNSProvider returns a DNSProvider instance configured for Liquid Web.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.GetWithFallback(
		[]string{EnvUsername, altEnvName(EnvUsername)},
		[]string{EnvPassword, altEnvName(EnvPassword)},
	)
	if err != nil {
		return nil, fmt.Errorf("liquidweb: %w", err)
	}

	config := NewDefaultConfig()
	config.BaseURL = env.GetOneWithFallback(EnvURL, defaultBaseURL, env.ParseString, altEnvName(EnvURL))
	config.Username = values[EnvUsername]
	config.Password = values[EnvPassword]
	config.Zone = env.GetOneWithFallback(EnvZone, "", env.ParseString, altEnvName(EnvZone))

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

// NewDNSProviderConfig return a DNSProvider instance configured for Liquid Web.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("liquidweb: the configuration of the DNS provider is nil")
	}

	if config.BaseURL == "" {
		config.BaseURL = defaultBaseURL
	}

	client, err := lw.NewAPI(config.Username, config.Password, config.BaseURL, int(config.HTTPTimeout.Seconds()))
	if err != nil {
		return nil, fmt.Errorf("liquidweb: could not create Liquid Web API client: %w", err)
	}

	return &DNSProvider{
		config:    config,
		recordIDs: make(map[string]int),
		client:    client,
	}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (time.Duration, time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// Present creates a TXT record using the specified parameters.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	params := &network.DNSRecordParams{
		Name:  dns01.UnFqdn(info.EffectiveFQDN),
		RData: strconv.Quote(info.Value),
		Type:  "TXT",
		Zone:  d.config.Zone,
		TTL:   d.config.TTL,
	}

	if params.Zone == "" {
		bestZone, err := d.findZone(params.Name)
		if err != nil {
			return fmt.Errorf("liquidweb: %w", err)
		}

		params.Zone = bestZone
	}

	dnsEntry, err := d.client.NetworkDNS.Create(params)
	if err != nil {
		return fmt.Errorf("liquidweb: could not create TXT record: %w", err)
	}

	d.recordIDsMu.Lock()
	d.recordIDs[token] = int(dnsEntry.ID)
	d.recordIDsMu.Unlock()

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	d.recordIDsMu.Lock()
	recordID, ok := d.recordIDs[token]
	d.recordIDsMu.Unlock()

	if !ok {
		return fmt.Errorf("liquidweb: unknown record ID for '%s'", domain)
	}

	params := &network.DNSRecordParams{ID: recordID}
	_, err := d.client.NetworkDNS.Delete(params)
	if err != nil {
		return fmt.Errorf("liquidweb: could not remove TXT record: %w", err)
	}

	d.recordIDsMu.Lock()
	delete(d.recordIDs, token)
	d.recordIDsMu.Unlock()

	return nil
}

func (d *DNSProvider) findZone(domain string) (string, error) {
	zones, err := d.client.NetworkDNSZone.ListAll()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve zones for account: %w", err)
	}

	// filter the zones on the account to only ones that match
	var zs []network.DNSZone
	for _, item := range zones.Items {
		if strings.HasSuffix(domain, item.Name) {
			zs = append(zs, item)
		}
	}

	if len(zs) < 1 {
		return "", fmt.Errorf("no valid zone in account for certificate '%s'", domain)
	}

	// powerdns _only_ looks for records on the longest matching subdomain zone aka,
	// for test.sub.example.com if sub.example.com exists,
	// it will look there it will not look atexample.com even if it also exists
	sort.Slice(zs, func(i, j int) bool {
		return len(zs[i].Name) > len(zs[j].Name)
	})

	return zs[0].Name, nil
}

func altEnvName(v string) string {
	return strings.ReplaceAll(v, envNamespace, altEnvNamespace)
}
