package legox

import (
	"fmt"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	jsoniter "github.com/json-iterator/go"
)

// NewDNSChallengeProviderByName Factory for DNS providers.
func NewDNSChallengeProviderByName(name string, config []byte) (challenge.Provider, error) {
	switch name {
	case "aliyun":
		var alidnsConfig AlidnsConfig
		err := jsoniter.Unmarshal(config, &alidnsConfig)
		if err != nil {
			return nil, err
		}
		cfg := alidns.NewDefaultConfig()
		cfg.APIKey = alidnsConfig.AccessKey
		cfg.SecretKey = alidnsConfig.SecretKey
		return alidns.NewDNSProviderConfig(cfg)
	default:
		return nil, fmt.Errorf("unrecognized DNS provider: %s", name)
	}
}

func GetDNSChallengeProviderList() string {
	return `[{"type":"alidns","template":"{\"accessKey\": \"\",     \"secretKey\": \"\" }"}]`
}
