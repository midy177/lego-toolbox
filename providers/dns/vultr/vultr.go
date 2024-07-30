// Package vultr implements a DNS provider for solving the DNS-01 challenge using the Vultr DNS.
// See https://www.vultr.com/api/#dns
package vultr

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/vultr/govultr/v3"
	"golang.org/x/oauth2"
)

// Environment variables names.
const (
	envNamespace = "VULTR_"

	EnvAPIKey = envNamespace + "API_KEY"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	APIKey             string        `yaml:"apiKey"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	TTL                int           `yaml:"ttl"`
	HTTPClient         *http.Client  `yaml:"-"`
	HTTPTimeout        time.Duration `yaml:"httpTimeout"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt(EnvTTL, dns01.DefaultTTL),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, dns01.DefaultPropagationTimeout),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, dns01.DefaultPollingInterval),
		HTTPTimeout:        env.GetOrDefaultSecond(EnvHTTPTimeout, 30*time.Second),
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		TTL:                dns01.DefaultTTL,
		PropagationTimeout: dns01.DefaultPropagationTimeout,
		PollingInterval:    dns01.DefaultPollingInterval,
		HTTPTimeout:        30 * time.Second,
	}
}

func GetYamlTemple() string {
	return `# config.yaml
apiKey: "your_api_key"                      # API 密钥
propagationTimeout: 60s                     # 传播超时时间，单位为秒
pollingInterval: 20s                        # 轮询间隔时间，单位为秒
ttl: 120                                    # TTL 值，单位为秒
httpTimeout: 30s                            # HTTP 超时时间，单位为秒`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *govultr.Client
}

// NewDNSProvider returns a DNSProvider instance with a configured Vultr client.
// Authentication uses the VULTR_API_KEY environment variable.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvAPIKey)
	if err != nil {
		return nil, fmt.Errorf("vultr: %w", err)
	}

	config := NewDefaultConfig()
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

// NewDNSProviderConfig return a DNSProvider instance configured for Vultr.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("vultr: the configuration of the DNS provider is nil")
	}

	if config.APIKey == "" {
		return nil, errors.New("vultr: credentials missing")
	}

	authClient := OAuthStaticAccessToken(config.HTTPClient, config.APIKey)
	authClient.Timeout = config.HTTPTimeout

	client := govultr.NewClient(authClient)

	return &DNSProvider{client: client, config: config}, nil
}

// Present creates a TXT record to fulfill the DNS-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	ctx := context.Background()

	info := dns01.GetChallengeInfo(domain, keyAuth)

	// TODO(ldez) replace domain by FQDN to follow CNAME.
	zoneDomain, err := d.getHostedZone(ctx, domain)
	if err != nil {
		return fmt.Errorf("vultr: %w", err)
	}

	subDomain, err := dns01.ExtractSubDomain(info.EffectiveFQDN, zoneDomain)
	if err != nil {
		return fmt.Errorf("vultr: %w", err)
	}

	req := govultr.DomainRecordReq{
		Name:     subDomain,
		Type:     "TXT",
		Data:     `"` + info.Value + `"`,
		TTL:      d.config.TTL,
		Priority: func(v int) *int { return &v }(0),
	}

	_, resp, err := d.client.DomainRecord.Create(ctx, zoneDomain, &req)
	if err != nil {
		return fmt.Errorf("vultr: %w", extendError(resp, err))
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	ctx := context.Background()

	info := dns01.GetChallengeInfo(domain, keyAuth)

	// TODO(ldez) replace domain by FQDN to follow CNAME.
	zoneDomain, records, err := d.findTxtRecords(ctx, domain, info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("vultr: %w", err)
	}

	var allErr []string
	for _, rec := range records {
		err := d.client.DomainRecord.Delete(ctx, zoneDomain, rec.ID)
		if err != nil {
			allErr = append(allErr, err.Error())
		}
	}

	if len(allErr) > 0 {
		return errors.New(strings.Join(allErr, ": "))
	}

	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

func (d *DNSProvider) getHostedZone(ctx context.Context, domain string) (string, error) {
	listOptions := &govultr.ListOptions{PerPage: 25}

	var hostedDomain govultr.Domain

	for {
		domains, meta, resp, err := d.client.Domain.List(ctx, listOptions)
		if err != nil {
			return "", extendError(resp, err)
		}

		for _, dom := range domains {
			if strings.HasSuffix(domain, dom.Domain) && len(dom.Domain) > len(hostedDomain.Domain) {
				hostedDomain = dom
			}
		}

		if domain == hostedDomain.Domain {
			break
		}

		if meta.Links.Next == "" {
			break
		}

		listOptions.Cursor = meta.Links.Next
	}

	if hostedDomain.Domain == "" {
		return "", fmt.Errorf("no matching domain found for domain %s", domain)
	}

	return hostedDomain.Domain, nil
}

func (d *DNSProvider) findTxtRecords(ctx context.Context, domain, fqdn string) (string, []govultr.DomainRecord, error) {
	zoneDomain, err := d.getHostedZone(ctx, domain)
	if err != nil {
		return "", nil, err
	}

	subDomain, err := dns01.ExtractSubDomain(fqdn, zoneDomain)
	if err != nil {
		return "", nil, err
	}

	listOptions := &govultr.ListOptions{PerPage: 25}

	var records []govultr.DomainRecord
	for {
		result, meta, resp, err := d.client.DomainRecord.List(ctx, zoneDomain, listOptions)
		if err != nil {
			return "", records, extendError(resp, err)
		}

		for _, record := range result {
			if record.Type == "TXT" && record.Name == subDomain {
				records = append(records, record)
			}
		}

		if meta.Links.Next == "" {
			break
		}

		listOptions.Cursor = meta.Links.Next
	}

	return zoneDomain, records, nil
}

func OAuthStaticAccessToken(client *http.Client, accessToken string) *http.Client {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	client.Transport = &oauth2.Transport{
		Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken}),
		Base:   client.Transport,
	}

	return client
}

func extendError(resp *http.Response, err error) error {
	msg := "API call failed"
	if resp != nil {
		msg += fmt.Sprintf(" (%d)", resp.StatusCode)
	}

	return fmt.Errorf("%s: %w", msg, err)
}
