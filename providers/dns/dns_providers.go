package dns

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
	"lego-toolbox/providers/dns/directadmin"
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

// NewDNSChallengeProviderByName Factory for DNS providers.
func NewDNSChallengeProviderByName(name string) (challenge.Provider, error) {
	switch name {
	case "acme-dns": // TODO(ldez): remove "-" in v5
		return acmedns.NewDNSProvider()
	case "alidns":
		return alidns.NewDNSProvider()
	case "allinkl":
		return allinkl.NewDNSProvider()
	case "arvancloud":
		return arvancloud.NewDNSProvider()
	case "azure":
		return azure.NewDNSProvider()
	case "azuredns":
		return azuredns.NewDNSProvider()
	case "auroradns":
		return auroradns.NewDNSProvider()
	case "autodns":
		return autodns.NewDNSProvider()
	case "bindman":
		return bindman.NewDNSProvider()
	case "bluecat":
		return bluecat.NewDNSProvider()
	case "brandit":
		return brandit.NewDNSProvider()
	case "bunny":
		return bunny.NewDNSProvider()
	case "checkdomain":
		return checkdomain.NewDNSProvider()
	case "civo":
		return civo.NewDNSProvider()
	case "clouddns":
		return clouddns.NewDNSProvider()
	case "cloudflare":
		return cloudflare.NewDNSProvider()
	case "cloudns":
		return cloudns.NewDNSProvider()
	case "cloudru":
		return cloudru.NewDNSProvider()
	case "cloudxns":
		return cloudxns.NewDNSProvider()
	case "conoha":
		return conoha.NewDNSProvider()
	case "constellix":
		return constellix.NewDNSProvider()
	case "cpanel":
		return cpanel.NewDNSProvider()
	case "derak":
		return derak.NewDNSProvider()
	case "desec":
		return desec.NewDNSProvider()
	case "designate":
		return designate.NewDNSProvider()
	case "digitalocean":
		return digitalocean.NewDNSProvider()
	case "directadmin":
		return directadmin.NewDNSProvider()
	case "dnshomede":
		return dnshomede.NewDNSProvider()
	case "dnsimple":
		return dnsimple.NewDNSProvider()
	case "dnsmadeeasy":
		return dnsmadeeasy.NewDNSProvider()
	case "dnspod":
		return dnspod.NewDNSProvider()
	case "dode":
		return dode.NewDNSProvider()
	case "domeneshop", "domainnameshop":
		return domeneshop.NewDNSProvider()
	case "dreamhost":
		return dreamhost.NewDNSProvider()
	case "duckdns":
		return duckdns.NewDNSProvider()
	case "dyn":
		return dyn.NewDNSProvider()
	case "dynu":
		return dynu.NewDNSProvider()
	case "easydns":
		return easydns.NewDNSProvider()
	case "edgedns", "fastdns": // "fastdns" is for compatibility with v3, must be dropped in v5
		return edgedns.NewDNSProvider()
	case "efficientip":
		return efficientip.NewDNSProvider()
	case "epik":
		return epik.NewDNSProvider()
	case "exec":
		return exec.NewDNSProvider()
	case "exoscale":
		return exoscale.NewDNSProvider()
	case "freemyip":
		return freemyip.NewDNSProvider()
	case "gandi":
		return gandi.NewDNSProvider()
	case "gandiv5":
		return gandiv5.NewDNSProvider()
	case "gcloud":
		return gcloud.NewDNSProvider()
	case "gcore":
		return gcore.NewDNSProvider()
	case "glesys":
		return glesys.NewDNSProvider()
	case "godaddy":
		return godaddy.NewDNSProvider()
	case "googledomains":
		return googledomains.NewDNSProvider()
	case "hetzner":
		return hetzner.NewDNSProvider()
	case "hostingde":
		return hostingde.NewDNSProvider()
	case "hosttech":
		return hosttech.NewDNSProvider()
	case "httpnet":
		return httpnet.NewDNSProvider()
	case "httpreq":
		return httpreq.NewDNSProvider()
	case "hurricane":
		return hurricane.NewDNSProvider()
	case "hyperone":
		return hyperone.NewDNSProvider()
	case "ibmcloud":
		return ibmcloud.NewDNSProvider()
	case "iij":
		return iij.NewDNSProvider()
	case "iijdpf":
		return iijdpf.NewDNSProvider()
	case "infoblox":
		return infoblox.NewDNSProvider()
	case "infomaniak":
		return infomaniak.NewDNSProvider()
	case "internetbs":
		return internetbs.NewDNSProvider()
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
		return route53.NewDNSProvider()
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
		return tencentcloud.NewDNSProvider()
	case "transip":
		return transip.NewDNSProvider()
	case "ultradns":
		return ultradns.NewDNSProvider()
	case "variomedia":
		return variomedia.NewDNSProvider()
	case "vegadns":
		return vegadns.NewDNSProvider()
	case "vercel":
		return vercel.NewDNSProvider()
	case "versio":
		return versio.NewDNSProvider()
	case "vinyldns":
		return vinyldns.NewDNSProvider()
	case "vkcloud":
		return vkcloud.NewDNSProvider()
	case "vscale":
		return vscale.NewDNSProvider()
	case "vultr":
		return vultr.NewDNSProvider()
	case "webnames":
		return webnames.NewDNSProvider()
	case "websupport":
		return websupport.NewDNSProvider()
	case "wedos":
		return wedos.NewDNSProvider()
	case "yandex":
		return yandex.NewDNSProvider()
	case "yandex360":
		return yandex360.NewDNSProvider()
	case "yandexcloud":
		return yandexcloud.NewDNSProvider()
	case "zoneee":
		return zoneee.NewDNSProvider()
	case "zonomi":
		return zonomi.NewDNSProvider()
	default:
		return nil, fmt.Errorf("unrecognized DNS provider: %s", name)
	}
}
