package legox

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	jsoniter "github.com/json-iterator/go"
	"github.com/suyuan32/simple-admin-core/cert/ent"
	"github.com/suyuan32/simple-admin-core/cert/ent/domaincert"
	"strings"
)

type LegoUser struct {
	Account    *ent.AcmeAccount
	LegoClient *lego.Client
}

func FromAccountUser(a *ent.AcmeAccount) *LegoUser {
	return &LegoUser{
		Account: a,
	}
}
func (l *LegoUser) GetEmail() string {
	return l.Account.Email
}
func (l *LegoUser) GetRegistration() *registration.Resource {
	var reg registration.Resource
	err := jsoniter.Unmarshal(l.Account.Reg, &reg)
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
	if len(l.Account.PrivateKey) != 0 {
		return errors.New("the account has a private key")
	}
	err := l.genPrivateKey()
	if err != nil {
		return err
	}
	err = l.newLegoClient(domaincert.EncTypeEC384)
	if err != nil {
		return err
	}
	// New users will need to register
	reg, err := l.LegoClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	regBytes, err := jsoniter.Marshal(reg)
	if err != nil {
		return err
	}
	l.Account.Reg = regBytes
	return nil
}

func (l *LegoUser) QueryUserRegistration() (*registration.Resource, error) {
	reg, err := l.LegoClient.Registration.QueryRegistration()
	if err != nil {
		return nil, err
	}
	return reg, err
}

func (l *LegoUser) ObtainCertificate(cert *ent.DomainCert, provider challenge.Provider) error {
	err := l.newLegoClient(cert.EncType)
	if err != nil {
		return err
	}
	err = l.LegoClient.Challenge.SetDNS01Provider(provider)
	if err != nil {
		return err
	}
	domains := strings.Split(cert.Domains, ",")
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}
	certificates, err := l.LegoClient.Certificate.Obtain(request)
	if err != nil {
		return err
	}
	cert.CertDomain = certificates.Domain
	cert.CertURL = certificates.CertURL
	cert.CertStableURL = certificates.CertStableURL
	cert.PrivateKey = certificates.PrivateKey
	cert.Certificate = certificates.Certificate
	cert.Csr = certificates.CSR
	return nil
}

func (l *LegoUser) genPrivateKey() error {
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

func (l *LegoUser) newLegoClient(KeyType domaincert.EncType) error {
	config := lego.NewConfig(l)
	config.Certificate.KeyType = chooseKeyType(KeyType)
	client, err := lego.NewClient(config)
	if err != nil {
		return err
	}
	l.LegoClient = client
	return nil
}

func chooseKeyType(expr domaincert.EncType) certcrypto.KeyType {
	switch expr {
	case domaincert.EncTypeEC256:
		return certcrypto.EC256
	case domaincert.EncTypeEC384:
		return certcrypto.EC384
	case domaincert.EncTypeRSA2048:
		return certcrypto.RSA2048
	case domaincert.EncTypeRSA3072:
		return certcrypto.RSA3072
	case domaincert.EncTypeRSA4096:
		return certcrypto.RSA4096
	case domaincert.EncTypeRSA8192:
		return certcrypto.RSA8192
	}
	return certcrypto.RSA2048
}
