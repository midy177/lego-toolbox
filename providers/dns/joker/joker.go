// Package joker implements a DNS provider for solving the DNS-01 challenge using joker.com.
package joker

import (
	"gopkg.in/yaml.v3"
	"net/http"
	"os"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
)

// Environment variables names.
const (
	envNamespace = "JOKER_"

	EnvAPIKey   = envNamespace + "API_KEY"
	EnvUsername = envNamespace + "USERNAME"
	EnvPassword = envNamespace + "PASSWORD"
	EnvDebug    = envNamespace + "DEBUG"
	EnvMode     = envNamespace + "API_MODE"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvSequenceInterval   = envNamespace + "SEQUENCE_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

const (
	modeDMAPI = "DMAPI"
	modeSVC   = "SVC"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	Debug              bool          `yaml:"-"`
	APIKey             string        `yaml:"apiKey"`
	Username           string        `yaml:"username"`
	Password           string        `yaml:"password"`
	APIMode            string        `yaml:"apiMode"`
	PropagationTimeout time.Duration `yaml:"propagationTimeout"`
	PollingInterval    time.Duration `yaml:"pollingInterval"`
	SequenceInterval   time.Duration `yaml:"sequenceInterval"`
	TTL                int           `yaml:"ttl"`
	HTTPClient         *http.Client  `yaml:"-"`
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		APIMode:            env.GetOrDefaultString(EnvMode, modeDMAPI),
		Debug:              env.GetOrDefaultBool(EnvDebug, false),
		TTL:                env.GetOrDefaultInt(EnvTTL, dns01.DefaultTTL),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, 2*time.Minute),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, dns01.DefaultPollingInterval),
		SequenceInterval:   env.GetOrDefaultSecond(EnvSequenceInterval, dns01.DefaultPropagationTimeout),
		HTTPClient: &http.Client{
			Timeout: env.GetOrDefaultSecond(EnvHTTPTimeout, 60*time.Second),
		},
	}
}

// DefaultConfig returns a default configuration for the DNSProvider.
func DefaultConfig() *Config {
	return &Config{
		APIMode:            modeDMAPI,
		Debug:              false,
		TTL:                dns01.DefaultTTL,
		PropagationTimeout: 2 * time.Minute,
		PollingInterval:    dns01.DefaultPollingInterval,
		SequenceInterval:   dns01.DefaultPropagationTimeout,
		HTTPClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func GetYamlTemple() string {
	return `# YAML 示例
apiKey: "your_api_key_here"           # API 密钥，用于身份验证和授权
username: "your_username_here"        # 用户名，用于身份验证
password: "your_password_here"        # 密码，用于身份验证
apiMode: "DMAPI"                 # API 模式，例如 "DMAPI" 或 "SVC"
propagationTimeout: 60s               # 传播超时时间，表示系统等待变化传播的最长时间
pollingInterval: 2s                   # 轮询间隔时间，表示系统定期检查更新的时间间隔
sequenceInterval: 60s                 # 序列间隔时间
ttl: 120                              # TTL（Time to Live），表示数据或缓存的有效时间（以秒为单位）`
}

// NewDNSProvider returns a DNSProvider instance configured for Joker.
// Credentials must be passed in the environment variable JOKER_API_KEY.
func NewDNSProvider() (challenge.ProviderTimeout, error) {
	if os.Getenv(EnvMode) == modeSVC {
		return newSvcProvider()
	}

	return newDmapiProvider()
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

// NewDNSProviderConfig return a DNSProvider instance configured for Joker.
func NewDNSProviderConfig(config *Config) (challenge.ProviderTimeout, error) {
	if config.APIMode == modeSVC {
		return newSvcProviderConfig(config)
	}

	return newDmapiProviderConfig(config)
}
