package legotoolbox

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	jsoniter "github.com/json-iterator/go"
)

// LegoAccount is the model entity for the LegoAccount schema.
type LegoAccount struct {
	// Email | 邮箱
	Email string `json:"email,omitempty"`
	// Private key | 私钥
	PrivateKey string `json:"private_key,omitempty"`
	// Reg info | 注册信息
	Registration []byte `json:"registration,omitempty"`
}

// CertificateConfig is the model entity for the DomainCert schema.
type CertificateConfig struct {
	// Subject Alternative Name | 证书域名扩展
	SAN []string `json:"san,omitempty"`
	// common name | 证书域名通用名称
	CommonDomain string `json:"common_domain,omitempty"`
	// encryption type | 证书加密方式
	EncType EncType `json:"enc_type,omitempty"`
	// Cert url | 证书网址
	CertURL string `json:"cert_url,omitempty"`
	// Cert stable url | 证书稳定网址
	CertStableURL string `json:"cert_stable_url,omitempty"`
	// Private key | 证书私钥
	PrivateKey []byte `json:"private_key,omitempty"`
	// Certificate | 证书链
	Certificate []byte `json:"certificate,omitempty"`
	// Issuer certificate | 发行人证书
	IssuerCertificate []byte `json:"issuer_certificate,omitempty"`
	// CSR | 证书签名请求
	CSR []byte `json:"csr,omitempty"`
}

type LegoUser struct {
	Account *LegoAccount
	Client  *lego.Client
}

func NewUserFromAccount(acc *LegoAccount) *LegoUser {
	return &LegoUser{
		Account: acc,
	}
}
func (l *LegoUser) GetEmail() string {
	return l.Account.Email
}
func (l *LegoUser) GetRegistration() *registration.Resource {
	var reg registration.Resource
	err := jsoniter.Unmarshal(l.Account.Registration, &reg)
	if err != nil {
		return nil
	}
	return &reg
}
func (l *LegoUser) GetPrivateKey() crypto.PrivateKey {
	decBytes, err := base64.StdEncoding.DecodeString(l.Account.PrivateKey)
	if err != nil {
		return nil
	}
	priKey, err := x509.ParseECPrivateKey(decBytes)
	if err != nil {
		return nil
	}
	return priKey
}

func (l *LegoUser) RegisterNewUser() error {
	if len(l.Account.PrivateKey) == 0 {
		err := l.GeneratePrivateKey()
		if err != nil {
			return err
		}
	}

	if l.Client == nil {
		err := l.NewClient(EC384)
		if err != nil {
			return err
		}
	}

	// New users will need to register
	reg, err := l.Client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	regBytes, err := jsoniter.Marshal(reg)
	if err != nil {
		return err
	}
	l.Account.Registration = regBytes
	return nil
}

func (l *LegoUser) QueryUserRegistration() (*registration.Resource, error) {
	reg, err := l.Client.Registration.QueryRegistration()
	if err != nil {
		return nil, err
	}
	return reg, err
}

func (l *LegoUser) ObtainCertificate(certCfg *CertificateConfig, provider challenge.Provider) error {
	if l.Client == nil {
		err := l.NewClient(certCfg.EncType)
		if err != nil {
			return err
		}
	}

	err := l.Client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		return err
	}
	request := certificate.ObtainRequest{
		Domains: certCfg.SAN,
		Bundle:  true,
	}
	certificates, err := l.Client.Certificate.Obtain(request)
	if err != nil {
		return err
	}
	certCfg.CommonDomain = certificates.Domain
	certCfg.CertURL = certificates.CertURL
	certCfg.CertStableURL = certificates.CertStableURL
	certCfg.PrivateKey = certificates.PrivateKey
	certCfg.Certificate = certificates.Certificate
	certCfg.CSR = certificates.CSR
	return nil
}

func (l *LegoUser) GeneratePrivateKey() error {
	// Create a user. New accounts need an email and private key to start.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	derBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}
	l.Account.PrivateKey = base64.StdEncoding.EncodeToString(derBytes)
	return nil
}

func (l *LegoUser) NewClient(KeyType EncType) error {
	config := lego.NewConfig(l)
	config.Certificate.KeyType = ConvertKeyType(KeyType)
	client, err := lego.NewClient(config)
	if err != nil {
		return err
	}
	l.Client = client
	return nil
}
