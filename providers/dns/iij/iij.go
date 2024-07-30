// Package iij implements a DNS provider for solving the DNS-01 challenge using IIJ DNS.
package iij

import (
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/iij/doapi"
	"github.com/iij/doapi/protocol"
)

// Environment variables names.
const (
	envNamespace = "IIJ_"

	EnvAPIAccessKey  = envNamespace + "API_ACCESS_KEY"
	EnvAPISecretKey  = envNamespace + "API_SECRET_KEY"
	EnvDoServiceCode = envNamespace + "DO_SERVICE_CODE"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	AccessKey          string        `yaml:"accessKey"`
	SecretKey          string        `yaml:"secretKey"`
	DoServiceCode      string        `yaml:"doServiceCode"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	TTL                int           `yaml:"ttl"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt(EnvTTL, 300),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, 2*time.Minute),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, 4*time.Second),
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		TTL:                300,
		PropagationTimeout: 2 * time.Minute,
		PollingInterval:    4 * time.Second,
	}
}

func GetYamlTemple() string {
	return `# 配置文件模板
# 访问密钥，用于身份验证
accessKey: "your_access_key"
# 秘密密钥，用于身份验证
secretKey: "your_secret_key"
# 服务代码，用于特定的服务操作
doServiceCode: "your_service_code"
# 传播超时，设置一个时间段，例如：10s, 1m
propagationTimeout: "2m"
# 轮询间隔，设置一个时间段，例如：5s, 30s
pollingInterval: "4s"
# TTL (Time To Live)，设置一个整数值
ttl: 300`
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	api    *doapi.API
	config *Config
}

// NewDNSProvider returns a DNSProvider instance configured for IIJ DNS.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvAPIAccessKey, EnvAPISecretKey, EnvDoServiceCode)
	if err != nil {
		return nil, fmt.Errorf("iij: %w", err)
	}

	config := NewDefaultConfig()
	config.AccessKey = values[EnvAPIAccessKey]
	config.SecretKey = values[EnvAPISecretKey]
	config.DoServiceCode = values[EnvDoServiceCode]

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
	if config.SecretKey == "" || config.AccessKey == "" || config.DoServiceCode == "" {
		return nil, errors.New("iij: credentials missing")
	}

	return &DNSProvider{
		api:    doapi.NewAPI(config.AccessKey, config.SecretKey),
		config: config,
	}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// Present creates a TXT record using the specified parameters.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	// TODO(ldez) replace domain by FQDN to follow CNAME.
	err := d.addTxtRecord(domain, info.Value)
	if err != nil {
		return fmt.Errorf("iij: %w", err)
	}
	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	// TODO(ldez) replace domain by FQDN to follow CNAME.
	err := d.deleteTxtRecord(domain, info.Value)
	if err != nil {
		return fmt.Errorf("iij: %w", err)
	}
	return nil
}

func (d *DNSProvider) addTxtRecord(domain, value string) error {
	zones, err := d.listZones()
	if err != nil {
		return err
	}

	// TODO(ldez) replace domain by FQDN to follow CNAME.
	owner, zone, err := splitDomain(domain, zones)
	if err != nil {
		return err
	}

	request := protocol.RecordAdd{
		DoServiceCode: d.config.DoServiceCode,
		ZoneName:      zone,
		Owner:         owner,
		TTL:           strconv.Itoa(d.config.TTL),
		RecordType:    "TXT",
		RData:         value,
	}

	response := &protocol.RecordAddResponse{}

	if err := doapi.Call(*d.api, request, response); err != nil {
		return err
	}

	return d.commit()
}

func (d *DNSProvider) deleteTxtRecord(domain, value string) error {
	zones, err := d.listZones()
	if err != nil {
		return err
	}

	owner, zone, err := splitDomain(domain, zones)
	if err != nil {
		return err
	}

	id, err := d.findTxtRecord(owner, zone, value)
	if err != nil {
		return err
	}

	request := protocol.RecordDelete{
		DoServiceCode: d.config.DoServiceCode,
		ZoneName:      zone,
		RecordID:      id,
	}

	response := &protocol.RecordDeleteResponse{}

	if err := doapi.Call(*d.api, request, response); err != nil {
		return err
	}

	return d.commit()
}

func (d *DNSProvider) commit() error {
	request := protocol.Commit{
		DoServiceCode: d.config.DoServiceCode,
	}

	response := &protocol.CommitResponse{}

	return doapi.Call(*d.api, request, response)
}

func (d *DNSProvider) findTxtRecord(owner, zone, value string) (string, error) {
	request := protocol.RecordListGet{
		DoServiceCode: d.config.DoServiceCode,
		ZoneName:      zone,
	}

	response := &protocol.RecordListGetResponse{}

	if err := doapi.Call(*d.api, request, response); err != nil {
		return "", err
	}

	var id string

	for _, record := range response.RecordList {
		if record.Owner == owner && record.RecordType == "TXT" && record.RData == "\""+value+"\"" {
			id = record.Id
		}
	}

	if id == "" {
		return "", fmt.Errorf("%s record in %s not found", owner, zone)
	}

	return id, nil
}

func (d *DNSProvider) listZones() ([]string, error) {
	request := protocol.ZoneListGet{
		DoServiceCode: d.config.DoServiceCode,
	}

	response := &protocol.ZoneListGetResponse{}

	if err := doapi.Call(*d.api, request, response); err != nil {
		return nil, err
	}

	return response.ZoneList, nil
}

func splitDomain(domain string, zones []string) (string, string, error) {
	parts := strings.Split(strings.Trim(domain, "."), ".")

	var owner string
	var zone string

	for i := range len(parts) - 1 {
		zone = strings.Join(parts[i:], ".")
		if slices.Contains(zones, zone) {
			baseOwner := strings.Join(parts[0:i], ".")
			if baseOwner != "" {
				baseOwner = "." + baseOwner
			}
			owner = "_acme-challenge" + baseOwner
			break
		}
	}

	if owner == "" {
		return "", "", fmt.Errorf("%s not found", domain)
	}

	return owner, zone, nil
}
