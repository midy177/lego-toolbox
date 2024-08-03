package legotoolbox

import (
	"fmt"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"lego-toolbox/providers/dns/acmedns"
	"lego-toolbox/providers/dns/alidns"
	"lego-toolbox/providers/dns/allinkl"
	"lego-toolbox/providers/dns/arvancloud"
	"lego-toolbox/providers/dns/auroradns"
	"lego-toolbox/providers/dns/autodns"
	"lego-toolbox/providers/dns/azure"
	"lego-toolbox/providers/dns/azuredns"
	"lego-toolbox/providers/dns/bindman"
	"lego-toolbox/providers/dns/bluecat"
	"lego-toolbox/providers/dns/brandit"
	"lego-toolbox/providers/dns/bunny"
	"lego-toolbox/providers/dns/checkdomain"
	"lego-toolbox/providers/dns/civo"
	"lego-toolbox/providers/dns/clouddns"
	"lego-toolbox/providers/dns/cloudflare"
	"lego-toolbox/providers/dns/cloudns"
	"lego-toolbox/providers/dns/cloudru"
	"lego-toolbox/providers/dns/cloudxns"
	"lego-toolbox/providers/dns/conoha"
	"lego-toolbox/providers/dns/constellix"
	"lego-toolbox/providers/dns/cpanel"
	"lego-toolbox/providers/dns/derak"
	"lego-toolbox/providers/dns/desec"
	"lego-toolbox/providers/dns/designate"
	"lego-toolbox/providers/dns/digitalocean"
	"lego-toolbox/providers/dns/dnshomede"
	"lego-toolbox/providers/dns/dnsimple"
	"lego-toolbox/providers/dns/dnsmadeeasy"
	"lego-toolbox/providers/dns/dnspod"
	"lego-toolbox/providers/dns/dode"
	"lego-toolbox/providers/dns/domeneshop"
	"lego-toolbox/providers/dns/dreamhost"
	"lego-toolbox/providers/dns/duckdns"
	"lego-toolbox/providers/dns/dyn"
	"lego-toolbox/providers/dns/dynu"
	"lego-toolbox/providers/dns/easydns"
	"lego-toolbox/providers/dns/edgedns"
	"lego-toolbox/providers/dns/efficientip"
	"lego-toolbox/providers/dns/epik"
	"lego-toolbox/providers/dns/exec"
	"lego-toolbox/providers/dns/exoscale"
	"lego-toolbox/providers/dns/freemyip"
	"lego-toolbox/providers/dns/gandi"
	"lego-toolbox/providers/dns/gandiv5"
	"lego-toolbox/providers/dns/gcloud"
	"lego-toolbox/providers/dns/gcore"
	"lego-toolbox/providers/dns/glesys"
	"lego-toolbox/providers/dns/godaddy"
	"lego-toolbox/providers/dns/googledomains"
	"lego-toolbox/providers/dns/hetzner"
	"lego-toolbox/providers/dns/hostingde"
	"lego-toolbox/providers/dns/hosttech"
	"lego-toolbox/providers/dns/httpnet"
	"lego-toolbox/providers/dns/httpreq"
	"lego-toolbox/providers/dns/hurricane"
	"lego-toolbox/providers/dns/hyperone"
	"lego-toolbox/providers/dns/ibmcloud"
	"lego-toolbox/providers/dns/iij"
	"lego-toolbox/providers/dns/iijdpf"
	"lego-toolbox/providers/dns/infoblox"
	"lego-toolbox/providers/dns/infomaniak"
	"lego-toolbox/providers/dns/internetbs"
	"lego-toolbox/providers/dns/inwx"
	"lego-toolbox/providers/dns/ionos"
	"lego-toolbox/providers/dns/ipv64"
	"lego-toolbox/providers/dns/iwantmyname"
	"lego-toolbox/providers/dns/joker"
	"lego-toolbox/providers/dns/liara"
	"lego-toolbox/providers/dns/lightsail"
	"lego-toolbox/providers/dns/linode"
	"lego-toolbox/providers/dns/liquidweb"
	"lego-toolbox/providers/dns/loopia"
	"lego-toolbox/providers/dns/luadns"
	"lego-toolbox/providers/dns/mailinabox"
	"lego-toolbox/providers/dns/metaname"
	"lego-toolbox/providers/dns/mydnsjp"
	"lego-toolbox/providers/dns/mythicbeasts"
	"lego-toolbox/providers/dns/namecheap"
	"lego-toolbox/providers/dns/namedotcom"
	"lego-toolbox/providers/dns/namesilo"
	"lego-toolbox/providers/dns/nearlyfreespeech"
	"lego-toolbox/providers/dns/netcup"
	"lego-toolbox/providers/dns/netlify"
	"lego-toolbox/providers/dns/nicmanager"
	"lego-toolbox/providers/dns/nifcloud"
	"lego-toolbox/providers/dns/njalla"
	"lego-toolbox/providers/dns/nodion"
	"lego-toolbox/providers/dns/ns1"
	"lego-toolbox/providers/dns/oraclecloud"
	"lego-toolbox/providers/dns/otc"
	"lego-toolbox/providers/dns/ovh"
	"lego-toolbox/providers/dns/pdns"
	"lego-toolbox/providers/dns/plesk"
	"lego-toolbox/providers/dns/porkbun"
	"lego-toolbox/providers/dns/rackspace"
	"lego-toolbox/providers/dns/rcodezero"
	"lego-toolbox/providers/dns/regru"
	"lego-toolbox/providers/dns/rfc2136"
	"lego-toolbox/providers/dns/rimuhosting"
	"lego-toolbox/providers/dns/route53"
	"lego-toolbox/providers/dns/safedns"
	"lego-toolbox/providers/dns/sakuracloud"
	"lego-toolbox/providers/dns/scaleway"
	"lego-toolbox/providers/dns/selectel"
	"lego-toolbox/providers/dns/selectelv2"
	"lego-toolbox/providers/dns/servercow"
	"lego-toolbox/providers/dns/shellrent"
	"lego-toolbox/providers/dns/simply"
	"lego-toolbox/providers/dns/sonic"
	"lego-toolbox/providers/dns/stackpath"
	"lego-toolbox/providers/dns/tencentcloud"
	"lego-toolbox/providers/dns/transip"
	"lego-toolbox/providers/dns/ultradns"
	"lego-toolbox/providers/dns/variomedia"
	"lego-toolbox/providers/dns/vegadns"
	"lego-toolbox/providers/dns/vercel"
	"lego-toolbox/providers/dns/versio"
	"lego-toolbox/providers/dns/vinyldns"
	"lego-toolbox/providers/dns/vkcloud"
	"lego-toolbox/providers/dns/vscale"
	"lego-toolbox/providers/dns/vultr"
	"lego-toolbox/providers/dns/webnames"
	"lego-toolbox/providers/dns/websupport"
	"lego-toolbox/providers/dns/wedos"
	"lego-toolbox/providers/dns/yandex"
	"lego-toolbox/providers/dns/yandex360"
	"lego-toolbox/providers/dns/yandexcloud"
	"lego-toolbox/providers/dns/zoneee"
	"lego-toolbox/providers/dns/zonomi"
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
		cfg, err := inwx.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return inwx.NewDNSProviderConfig(cfg)
	case "ionos":
		cfg, err := ionos.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return ionos.NewDNSProviderConfig(cfg)
	case "ipv64":
		cfg, err := ipv64.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return ipv64.NewDNSProviderConfig(cfg)
	case "iwantmyname":
		cfg, err := iwantmyname.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return iwantmyname.NewDNSProviderConfig(cfg)
	case "joker":
		cfg, err := joker.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return joker.NewDNSProviderConfig(cfg)
	case "liara":
		cfg, err := liara.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return liara.NewDNSProviderConfig(cfg)
	case "lightsail":
		// 不支持
		return lightsail.NewDNSProvider()
	case "linode", "linodev4": // "linodev4" is for compatibility with v3, must be dropped in v5
		cfg, err := linode.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return linode.NewDNSProviderConfig(cfg)
	case "liquidweb":
		cfg, err := liquidweb.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return liquidweb.NewDNSProviderConfig(cfg)
	case "loopia":
		cfg, err := loopia.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return loopia.NewDNSProviderConfig(cfg)
	case "luadns":
		cfg, err := luadns.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return luadns.NewDNSProviderConfig(cfg)
	case "mailinabox":
		cfg, err := mailinabox.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return mailinabox.NewDNSProviderConfig(cfg)
	case "manual":
		// 不支持
		return dns01.NewDNSProviderManual()
	case "metaname":
		cfg, err := metaname.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return metaname.NewDNSProviderConfig(cfg)
	case "mydnsjp":
		cfg, err := mydnsjp.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return mydnsjp.NewDNSProviderConfig(cfg)
	case "mythicbeasts":
		cfg, err := mythicbeasts.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return mythicbeasts.NewDNSProviderConfig(cfg)
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
		cfg, err := sonic.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return sonic.NewDNSProviderConfig(cfg)
	case "stackpath":
		cfg, err := stackpath.ParseConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		return stackpath.NewDNSProviderConfig(cfg)
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
