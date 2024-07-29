package dns

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
	"legotoolbox/providers/dns/directadmin"
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
