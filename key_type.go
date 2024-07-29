package legotoolbox

import "github.com/go-acme/lego/v4/certcrypto"

// EncType defines the type for the "enc_type" enum field.
type EncType string

// DefaultEncType RSA2048 is the default value of the EncType enum.
const DefaultEncType = RSA2048

// EncType values.
const (
	EC256   EncType = "EC256"
	EC384   EncType = "EC384"
	RSA2048 EncType = "RSA2048"
	RSA3072 EncType = "RSA3072"
	RSA4096 EncType = "RSA4096"
	RSA8192 EncType = "RSA8192"
)

func ConvertKeyType(expr EncType) certcrypto.KeyType {
	switch expr {
	case EC256:
		return certcrypto.EC256
	case EC384:
		return certcrypto.EC384
	case RSA2048:
		return certcrypto.RSA2048
	case RSA3072:
		return certcrypto.RSA3072
	case RSA4096:
		return certcrypto.RSA4096
	case RSA8192:
		return certcrypto.RSA8192
	}
	return certcrypto.RSA2048
}

func GetKeyTypeList() []string {
	return []string{"EC256", "EC384", "RSA2048", "RSA3072", "RSA4096", "RSA8192"}
}
