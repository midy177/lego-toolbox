package legotoolbox

import (
	"fmt"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"legotoolbox/providers/dns/acmedns"
	"legotoolbox/providers/dns/alidns"
	"legotoolbox/providers/dns/allinkl"
	"legotoolbox/providers/dns/arvancloud"
	"legotoolbox/providers/dns/auroradns"
	"legotoolbox/providers/dns/autodns"
	"legotoolbox/providers/dns/azure"
	"legotoolbox/providers/dns/azuredns"
	"legotoolbox/providers/dns/bindman"
	"legotoolbox/providers/dns/bluecat"
	"legotoolbox/providers/dns/brandit"
	"legotoolbox/providers/dns/bunny"
	"legotoolbox/providers/dns/checkdomain"
	"legotoolbox/providers/dns/civo"
	"legotoolbox/providers/dns/clouddns"
	"legotoolbox/providers/dns/cloudflare"
	"legotoolbox/providers/dns/cloudns"
	"legotoolbox/providers/dns/cloudru"
	"legotoolbox/providers/dns/cloudxns"
	"legotoolbox/providers/dns/conoha"
	"legotoolbox/providers/dns/constellix"
	"legotoolbox/providers/dns/cpanel"
	"legotoolbox/providers/dns/derak"
	"legotoolbox/providers/dns/desec"
	"legotoolbox/providers/dns/designate"
	"legotoolbox/providers/dns/digitalocean"
	"legotoolbox/providers/dns/dnshomede"
	"legotoolbox/providers/dns/dnsimple"
	"legotoolbox/providers/dns/dnsmadeeasy"
	"legotoolbox/providers/dns/dnspod"
	"legotoolbox/providers/dns/dode"
	"legotoolbox/providers/dns/domeneshop"
	"legotoolbox/providers/dns/dreamhost"
	"legotoolbox/providers/dns/duckdns"
	"legotoolbox/providers/dns/dyn"
	"legotoolbox/providers/dns/dynu"
	"legotoolbox/providers/dns/easydns"
	"legotoolbox/providers/dns/edgedns"
	"legotoolbox/providers/dns/efficientip"
	"legotoolbox/providers/dns/epik"
	"legotoolbox/providers/dns/exec"
	"legotoolbox/providers/dns/exoscale"
	"legotoolbox/providers/dns/freemyip"
	"legotoolbox/providers/dns/gandi"
	"legotoolbox/providers/dns/gandiv5"
	"legotoolbox/providers/dns/gcloud"
	"legotoolbox/providers/dns/gcore"
	"legotoolbox/providers/dns/glesys"
	"legotoolbox/providers/dns/godaddy"
	"legotoolbox/providers/dns/googledomains"
	"legotoolbox/providers/dns/hetzner"
	"legotoolbox/providers/dns/hostingde"
	"legotoolbox/providers/dns/hosttech"
	"legotoolbox/providers/dns/httpnet"
	"legotoolbox/providers/dns/httpreq"
	"legotoolbox/providers/dns/hurricane"
	"legotoolbox/providers/dns/hyperone"
	"legotoolbox/providers/dns/ibmcloud"
	"legotoolbox/providers/dns/iij"
	"legotoolbox/providers/dns/iijdpf"
	"legotoolbox/providers/dns/infoblox"
	"legotoolbox/providers/dns/infomaniak"
	"legotoolbox/providers/dns/internetbs"
	"legotoolbox/providers/dns/inwx"
	"legotoolbox/providers/dns/ionos"
	"legotoolbox/providers/dns/ipv64"
	"legotoolbox/providers/dns/iwantmyname"
	"legotoolbox/providers/dns/joker"
	"legotoolbox/providers/dns/liara"
	"legotoolbox/providers/dns/lightsail"
	"legotoolbox/providers/dns/linode"
	"legotoolbox/providers/dns/liquidweb"
	"legotoolbox/providers/dns/loopia"
	"legotoolbox/providers/dns/luadns"
	"legotoolbox/providers/dns/mailinabox"
	"legotoolbox/providers/dns/metaname"
	"legotoolbox/providers/dns/mydnsjp"
	"legotoolbox/providers/dns/mythicbeasts"
	"legotoolbox/providers/dns/namecheap"
	"legotoolbox/providers/dns/namedotcom"
	"legotoolbox/providers/dns/namesilo"
	"legotoolbox/providers/dns/nearlyfreespeech"
	"legotoolbox/providers/dns/netcup"
	"legotoolbox/providers/dns/netlify"
	"legotoolbox/providers/dns/nicmanager"
	"legotoolbox/providers/dns/nifcloud"
	"legotoolbox/providers/dns/njalla"
	"legotoolbox/providers/dns/nodion"
	"legotoolbox/providers/dns/ns1"
	"legotoolbox/providers/dns/oraclecloud"
	"legotoolbox/providers/dns/otc"
	"legotoolbox/providers/dns/ovh"
	"legotoolbox/providers/dns/pdns"
	"legotoolbox/providers/dns/plesk"
	"legotoolbox/providers/dns/porkbun"
	"legotoolbox/providers/dns/rackspace"
	"legotoolbox/providers/dns/rcodezero"
	"legotoolbox/providers/dns/regru"
	"legotoolbox/providers/dns/rfc2136"
	"legotoolbox/providers/dns/rimuhosting"
	"legotoolbox/providers/dns/route53"
	"legotoolbox/providers/dns/safedns"
	"legotoolbox/providers/dns/sakuracloud"
	"legotoolbox/providers/dns/scaleway"
	"legotoolbox/providers/dns/selectel"
	"legotoolbox/providers/dns/selectelv2"
	"legotoolbox/providers/dns/servercow"
	"legotoolbox/providers/dns/shellrent"
	"legotoolbox/providers/dns/simply"
	"legotoolbox/providers/dns/sonic"
	"legotoolbox/providers/dns/stackpath"
	"legotoolbox/providers/dns/tencentcloud"
	"legotoolbox/providers/dns/transip"
	"legotoolbox/providers/dns/ultradns"
	"legotoolbox/providers/dns/variomedia"
	"legotoolbox/providers/dns/vegadns"
	"legotoolbox/providers/dns/vercel"
	"legotoolbox/providers/dns/versio"
	"legotoolbox/providers/dns/vinyldns"
	"legotoolbox/providers/dns/vkcloud"
	"legotoolbox/providers/dns/vscale"
	"legotoolbox/providers/dns/vultr"
	"legotoolbox/providers/dns/webnames"
	"legotoolbox/providers/dns/websupport"
	"legotoolbox/providers/dns/wedos"
	"legotoolbox/providers/dns/yandex"
	"legotoolbox/providers/dns/yandex360"
	"legotoolbox/providers/dns/yandexcloud"
	"legotoolbox/providers/dns/zoneee"
	"legotoolbox/providers/dns/zonomi"
)

// NewDNSChallengeProviderByName Factory for DNS providers.rawConfig is yaml file
func NewDNSChallengeProviderByName(name string, rawConfig []byte) (challenge.Provider, error) {
	switch name {
	case "acme-dns":
		cfg, err := acmedns.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return acmedns.NewDNSProviderConfig(cfg)
	case "alidns":
		cfg, err := alidns.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return alidns.NewDNSProviderConfig(cfg)
	case "allinkl":
		cfg, err := allinkl.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return allinkl.NewDNSProviderConfig(cfg)
	case "arvancloud":
		cfg, err := arvancloud.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return arvancloud.NewDNSProviderConfig(cfg)
	case "azure":
		cfg, err := azure.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return azure.NewDNSProviderConfig(cfg)
	case "azuredns":
		cfg, err := azuredns.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return azuredns.NewDNSProviderConfig(cfg)
	case "auroradns":
		cfg, err := auroradns.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return auroradns.NewDNSProviderConfig(cfg)
	case "autodns":
		cfg, err := autodns.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return autodns.NewDNSProviderConfig(cfg)
	case "bindman":
		cfg, err := bindman.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return bindman.NewDNSProviderConfig(cfg)
	case "bluecat":
		cfg, err := bluecat.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return bluecat.NewDNSProviderConfig(cfg)
	case "brandit":
		cfg, err := brandit.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return brandit.NewDNSProviderConfig(cfg)
	case "bunny":
		cfg, err := bunny.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return bunny.NewDNSProviderConfig(cfg)
	case "checkdomain":
		cfg, err := checkdomain.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return checkdomain.NewDNSProviderConfig(cfg)
	case "civo":
		cfg, err := civo.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return civo.NewDNSProviderConfig(cfg)
	case "clouddns":
		cfg, err := clouddns.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return clouddns.NewDNSProviderConfig(cfg)
	case "cloudflare":
		cfg, err := cloudflare.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return cloudflare.NewDNSProviderConfig(cfg)
	case "cloudns":
		cfg, err := cloudns.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return cloudns.NewDNSProviderConfig(cfg)
	case "cloudru":
		cfg, err := cloudru.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return cloudru.NewDNSProviderConfig(cfg)
	case "cloudxns":
		cfg, err := cloudxns.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return cloudxns.NewDNSProviderConfig(cfg)
	case "conoha":
		cfg, err := conoha.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return conoha.NewDNSProviderConfig(cfg)
	case "constellix":
		cfg, err := constellix.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return constellix.NewDNSProviderConfig(cfg)
	case "cpanel":
		cfg, err := cpanel.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return cpanel.NewDNSProviderConfig(cfg)
	case "derak":
		cfg, err := derak.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return derak.NewDNSProviderConfig(cfg)
	case "desec":
		cfg, err := desec.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return desec.NewDNSProviderConfig(cfg)
	case "designate":
		cfg, err := designate.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return designate.NewDNSProviderConfig(cfg)
	case "digitalocean":
		cfg, err := digitalocean.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return digitalocean.NewDNSProviderConfig(cfg)
	case "dnshomede":
		cfg, err := dnshomede.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return dnshomede.NewDNSProviderConfig(cfg)
	case "dnsimple":
		cfg, err := dnsimple.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return dnsimple.NewDNSProviderConfig(cfg)
	case "dnsmadeeasy":
		cfg, err := dnsmadeeasy.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return dnsmadeeasy.NewDNSProviderConfig(cfg)
	case "dnspod":
		cfg, err := dnspod.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return dnspod.NewDNSProviderConfig(cfg)
	case "dode":
		cfg, err := dode.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return dode.NewDNSProviderConfig(cfg)
	case "domeneshop", "domainnameshop":
		cfg, err := domeneshop.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return domeneshop.NewDNSProviderConfig(cfg)
	case "dreamhost":
		cfg, err := dreamhost.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return dreamhost.NewDNSProviderConfig(cfg)
	case "duckdns":
		cfg, err := duckdns.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return duckdns.NewDNSProviderConfig(cfg)
	case "dyn":
		cfg, err := dyn.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return dyn.NewDNSProviderConfig(cfg)
	case "dynu":
		cfg, err := dynu.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return dynu.NewDNSProviderConfig(cfg)
	case "easydns":
		cfg, err := easydns.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return easydns.NewDNSProviderConfig(cfg)
	case "edgedns", "fastdns": // "fastdns" is for compatibility with v3, must be dropped in v5
		cfg, err := edgedns.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return edgedns.NewDNSProviderConfig(cfg)
	case "efficientip":
		cfg, err := efficientip.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return efficientip.NewDNSProviderConfig(cfg)
	case "epik":
		cfg, err := epik.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return epik.NewDNSProviderConfig(cfg)
	case "exec":
		cfg, err := exec.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return exec.NewDNSProviderConfig(cfg)
	case "exoscale":
		cfg, err := exoscale.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return exoscale.NewDNSProviderConfig(cfg)
	case "freemyip":
		cfg, err := freemyip.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return freemyip.NewDNSProviderConfig(cfg)
	case "gandi":
		cfg, err := gandi.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return gandi.NewDNSProviderConfig(cfg)
	case "gandiv5":
		cfg, err := gandiv5.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return gandiv5.NewDNSProviderConfig(cfg)
	case "gcloud":
		// 无法配置
		return gcloud.NewDNSProvider()
	case "gcore":
		cfg, err := gcore.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return gcore.NewDNSProviderConfig(cfg)
	case "glesys":
		return glesys.NewDNSProvider()
	case "godaddy":
		cfg, err := godaddy.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return godaddy.NewDNSProviderConfig(cfg)
	case "googledomains":
		cfg, err := googledomains.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return googledomains.NewDNSProviderConfig(cfg)
	case "hetzner":
		cfg, err := hetzner.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return hetzner.NewDNSProviderConfig(cfg)
	case "hostingde":
		cfg, err := hostingde.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return hostingde.NewDNSProviderConfig(cfg)
	case "hosttech":
		cfg, err := hosttech.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return hosttech.NewDNSProviderConfig(cfg)
	case "httpnet":
		cfg, err := httpnet.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return httpnet.NewDNSProviderConfig(cfg)
	case "httpreq":
		cfg, err := httpreq.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return httpreq.NewDNSProviderConfig(cfg)
	case "hurricane":
		cfg, err := hurricane.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return hurricane.NewDNSProviderConfig(cfg)
	case "hyperone":
		// 不支持
		return hyperone.NewDNSProvider()
	case "ibmcloud":
		cfg, err := ibmcloud.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return ibmcloud.NewDNSProviderConfig(cfg)
	case "iij":
		cfg, err := iij.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return iij.NewDNSProviderConfig(cfg)
	case "iijdpf":
		cfg, err := iijdpf.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return iijdpf.NewDNSProviderConfig(cfg)
	case "infoblox":
		cfg, err := infoblox.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return infoblox.NewDNSProviderConfig(cfg)
	case "infomaniak":
		cfg, err := infomaniak.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return infomaniak.NewDNSProviderConfig(cfg)
	case "internetbs":
		cfg, err := internetbs.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return internetbs.NewDNSProviderConfig(cfg)
	case "inwx":
		return inwx.NewDNSProvider()
	case "ionos":
		return ionos.NewDNSProvider()
	case "ipv64":
		return ipv64.NewDNSProvider()
	case "iwantmyname":
		return iwantmyname.NewDNSProvider()
	case "joker":
		return joker.NewDNSProvider()
	case "liara":
		return liara.NewDNSProvider()
	case "lightsail":
		return lightsail.NewDNSProvider()
	case "linode", "linodev4": // "linodev4" is for compatibility with v3, must be dropped in v5
		return linode.NewDNSProvider()
	case "liquidweb":
		return liquidweb.NewDNSProvider()
	case "loopia":
		return loopia.NewDNSProvider()
	case "luadns":
		return luadns.NewDNSProvider()
	case "mailinabox":
		return mailinabox.NewDNSProvider()
	case "manual":
		return dns01.NewDNSProviderManual()
	case "metaname":
		return metaname.NewDNSProvider()
	case "mydnsjp":
		return mydnsjp.NewDNSProvider()
	case "mythicbeasts":
		return mythicbeasts.NewDNSProvider()
	case "namecheap":
		return namecheap.NewDNSProvider()
	case "namedotcom":
		return namedotcom.NewDNSProvider()
	case "namesilo":
		return namesilo.NewDNSProvider()
	case "nearlyfreespeech":
		return nearlyfreespeech.NewDNSProvider()
	case "netcup":
		return netcup.NewDNSProvider()
	case "netlify":
		return netlify.NewDNSProvider()
	case "nicmanager":
		return nicmanager.NewDNSProvider()
	case "nifcloud":
		return nifcloud.NewDNSProvider()
	case "njalla":
		return njalla.NewDNSProvider()
	case "nodion":
		return nodion.NewDNSProvider()
	case "ns1":
		return ns1.NewDNSProvider()
	case "oraclecloud":
		return oraclecloud.NewDNSProvider()
	case "otc":
		return otc.NewDNSProvider()
	case "ovh":
		return ovh.NewDNSProvider()
	case "pdns":
		return pdns.NewDNSProvider()
	case "plesk":
		return plesk.NewDNSProvider()
	case "porkbun":
		return porkbun.NewDNSProvider()
	case "rackspace":
		return rackspace.NewDNSProvider()
	case "rcodezero":
		return rcodezero.NewDNSProvider()
	case "regru":
		return regru.NewDNSProvider()
	case "rfc2136":
		return rfc2136.NewDNSProvider()
	case "rimuhosting":
		return rimuhosting.NewDNSProvider()
	case "route53":
		cfg, err := route53.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return route53.NewDNSProviderConfig(cfg)
	case "safedns":
		return safedns.NewDNSProvider()
	case "sakuracloud":
		return sakuracloud.NewDNSProvider()
	case "scaleway":
		return scaleway.NewDNSProvider()
	case "selectel":
		return selectel.NewDNSProvider()
	case "selectelv2":
		return selectelv2.NewDNSProvider()
	case "servercow":
		return servercow.NewDNSProvider()
	case "shellrent":
		return shellrent.NewDNSProvider()
	case "simply":
		return simply.NewDNSProvider()
	case "sonic":
		return sonic.NewDNSProvider()
	case "stackpath":
		return stackpath.NewDNSProvider()
	case "tencentcloud":
		cfg, err := tencentcloud.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return tencentcloud.NewDNSProviderConfig(cfg)
	case "transip":
		return transip.NewDNSProvider()
	case "ultradns":
		cfg, err := ultradns.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return ultradns.NewDNSProviderConfig(cfg)
	case "variomedia":
		cfg, err := variomedia.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return variomedia.NewDNSProviderConfig(cfg)
	case "vegadns":
		cfg, err := vegadns.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return vegadns.NewDNSProviderConfig(cfg)
	case "vercel":
		cfg, err := vercel.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return vercel.NewDNSProviderConfig(cfg)
	case "versio":
		cfg, err := versio.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return versio.NewDNSProviderConfig(cfg)
	case "vinyldns":
		cfg, err := vinyldns.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return vinyldns.NewDNSProviderConfig(cfg)
	case "vkcloud":
		cfg, err := vkcloud.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return vkcloud.NewDNSProviderConfig(cfg)
	case "vscale":
		cfg, err := vscale.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return vscale.NewDNSProviderConfig(cfg)
	case "vultr":
		cfg, err := vultr.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return vultr.NewDNSProviderConfig(cfg)
	case "webnames":
		cfg, err := webnames.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return webnames.NewDNSProviderConfig(cfg)
	case "websupport":
		cfg, err := websupport.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return websupport.NewDNSProviderConfig(cfg)
	case "wedos":
		cfg, err := wedos.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return wedos.NewDNSProviderConfig(cfg)
	case "yandex":
		cfg, err := yandex.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return yandex.NewDNSProviderConfig(cfg)
	case "yandex360":
		cfg, err := yandex360.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return yandex360.NewDNSProviderConfig(cfg)
	case "yandexcloud":
		cfg, err := yandexcloud.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return yandexcloud.NewDNSProviderConfig(cfg)
	case "zoneee":
		cfg, err := zoneee.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return zoneee.NewDNSProviderConfig(cfg)
	case "zonomi":
		cfg, err := zonomi.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return zonomi.NewDNSProviderConfig(cfg)
	default:
		return nil, fmt.Errorf("unrecognized DNS provider: %s", name)
	}
}

// GetDNSChallengeProviderList Get a list of supported DNS challenge providers.
func GetDNSChallengeProviderList(name string, rawConfig []byte) []string {
	return []string{
		"acme-dns",
		"alidns",
		"allinkl",
		"arvancloud",
		"azure",
		"azuredns",
		"auroradns",
		"autodns",
		"bindman",
		"bluecat",
		"brandit",
		"bunny",
		"checkdomain",
		"civo",
		"clouddns",
		"cloudflare",
		"cloudns",
		"cloudru",
		"cloudxns",
		"conoha",
		"constellix",
		"cpanel",
		"derak",
		"desec",
		"designate",
		"digitalocean",
		"dnshomede",
		"dnsimple",
		"dnsmadeeasy",
		"dnspod",
		"dode",
		"domeneshop", "domainnameshop",
		"dreamhost",
		"duckdns",
		"dyn",
		"dynu",
		"easydns",
		"edgedns", "fastdns", // "fastdns" is for compatibility with v3, must be dropped in v5
		"efficientip",
		"epik",
		"exec",
		"exoscale",
		"freemyip",
		"gandi",
		"gandiv5",
		"gcloud",
		"gcore",
		"glesys",
		"godaddy",
		"googledomains",
		"hetzner",
		"hostingde",
		"hosttech",
		"httpnet",
		"httpreq",
		"hurricane",
		"hyperone",
		"ibmcloud",
		"iij",
		"iijdpf",
		"infoblox",
		"infomaniak",
		"internetbs",
		"inwx",
		"ionos",
		"ipv64",
		"iwantmyname",
		"joker",
		"liara",
		"lightsail",
		"linode", "linodev4", // "linodev4" is for compatibility with v3, must be dropped in v5
		"liquidweb",
		"loopia",
		"luadns",
		"mailinabox",
		"manual",
		"metaname",
		"mydnsjp",
		"mythicbeasts",
		"namecheap",
		"namedotcom",
		"namesilo",
		"nearlyfreespeech",
		"netcup",
		"netlify",
		"nicmanager",
		"nifcloud",
		"njalla",
		"nodion",
		"ns1",
		"oraclecloud",
		"otc",
		"ovh",
		"pdns",
		"plesk",
		"porkbun",
		"rackspace",
		"rcodezero",
		"regru",
		"rfc2136",
		"rimuhosting",
		"route53",
		"safedns",
		"sakuracloud",
		"scaleway",
		"selectel",
		"selectelv2",
		"servercow",
		"shellrent",
		"simply",
		"sonic",
		"stackpath",
		"tencentcloud",
		"transip",
		"ultradns",
		"variomedia",
		"vegadns",
		"vercel",
		"versio",
		"vinyldns",
		"vkcloud",
		"vscale",
		"vultr",
		"webnames",
		"websupport",
		"wedos",
		"yandex",
		"yandex360",
		"yandexcloud",
		"zoneee",
		"zonomi"}
}

// GetDNSChallengeProviderConfigTemple Get a list of supported DNS challenge providers.
func GetDNSChallengeProviderConfigTemple(name string) ([]byte, error) {
	switch name {
	case "acme-dns":

	case "alidns":

	case "allinkl":

	case "arvancloud":

	case "azure":

	case "azuredns":

	case "auroradns":

	case "autodns":

	case "bindman":

	case "bluecat":

	case "brandit":

	case "bunny":

	case "checkdomain":

	case "civo":

	case "clouddns":

	case "cloudflare":

	case "cloudns":

	case "cloudru":

	case "cloudxns":

	case "conoha":

	case "constellix":

	case "cpanel":

	case "derak":

	case "desec":

	case "designate":

	case "digitalocean":

	case "dnshomede":

	case "dnsimple":

	case "dnsmadeeasy":

	case "dnspod":

	case "dode":

	case "domeneshop", "domainnameshop":

	case "dreamhost":

	case "duckdns":

	case "dyn":

	case "dynu":

	case "easydns":

	case "edgedns", "fastdns": // "fastdns" is for compatibility with v3, must be dropped in v5

	case "efficientip":

	case "epik":

	case "exec":

	case "exoscale":

	case "freemyip":

	case "gandi":

	case "gandiv5":

	case "gcloud":

	case "gcore":

	case "glesys":

	case "godaddy":

	case "googledomains":

	case "hetzner":

	case "hostingde":

	case "hosttech":

	case "httpnet":

	case "httpreq":

	case "hurricane":

	case "hyperone":

	case "ibmcloud":

	case "iij":

	case "iijdpf":

	case "infoblox":

	case "infomaniak":

	case "internetbs":

	case "inwx":

	case "ionos":

	case "ipv64":

	case "iwantmyname":

	case "joker":

	case "liara":

	case "lightsail":

	case "linode", "linodev4": // "linodev4" is for compatibility with v3, must be dropped in v5

	case "liquidweb":

	case "loopia":

	case "luadns":

	case "mailinabox":

	case "manual":

	case "metaname":

	case "mydnsjp":

	case "mythicbeasts":

	case "namecheap":

	case "namedotcom":

	case "namesilo":

	case "nearlyfreespeech":

	case "netcup":

	case "netlify":

	case "nicmanager":

	case "nifcloud":

	case "njalla":

	case "nodion":

	case "ns1":

	case "oraclecloud":

	case "otc":

	case "ovh":

	case "pdns":

	case "plesk":

	case "porkbun":

	case "rackspace":

	case "rcodezero":

	case "regru":

	case "rfc2136":

	case "rimuhosting":

	case "route53":

	case "safedns":

	case "sakuracloud":

	case "scaleway":

	case "selectel":

	case "selectelv2":

	case "servercow":

	case "shellrent":

	case "simply":

	case "sonic":

	case "stackpath":

	case "tencentcloud":

	case "transip":

	case "ultradns":

	case "variomedia":

	case "vegadns":

	case "vercel":

	case "versio":

	case "vinyldns":

	case "vkcloud":

	case "vscale":

	case "vultr":

	case "webnames":

	case "websupport":

	case "wedos":

	case "yandex":

	case "yandex360":

	case "yandexcloud":

	case "zoneee":

	case "zonomi":

	default:
		return nil, fmt.Errorf("dns provider %q not supported", name)
	}

	return nil, nil
}
