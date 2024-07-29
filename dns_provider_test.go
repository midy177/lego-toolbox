package legotoolbox

import (
	"fmt"
	"legotoolbox/providers/dns/alidns"
	"testing"
)

func TestName(t *testing.T) {
	cfgStr := `{"api_key": "adjkhasfhfd", "secret_key": "asdfasdfasdf"}`
	config, err := alidns.ParseConfig([]byte(cfgStr))
	if err != nil {
		return
	}
	fmt.Println(config)
}
