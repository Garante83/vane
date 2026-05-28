package vssd

// ServiceSignature defines target fingerprints for specific home-server and enterprise services.
type ServiceSignature struct {
	Token          string
	DisplayName    string // Human-readable service name for output (e.g. "Proxmox VE", "Synology NAS")
	Ports          []int
	MDNSNames      []string
	MACOUIPrefixes []string
}

// Signatures is the static target fingerprint matrix for VSSD.
var Signatures = []ServiceSignature{
	{
		Token:       "pve",
		DisplayName: "Proxmox VE",
		Ports:       []int{8006},
		MDNSNames:   []string{"proxmox", "pve"},
	},
	{
		Token:          "nas",
		DisplayName:    "NAS",
		Ports:          []int{5000, 5001, 445, 80, 443},
		MDNSNames:      []string{"synology", "truenas", "freenas", "nas", "qnap", "nextcloud"},
		MACOUIPrefixes: []string{"00:11:32", "00:08:9b"}, // Synology & QNAP OUIs
	},
	{
		Token:          "pi",
		DisplayName:    "Raspberry Pi",
		Ports:          []int{22},
		MDNSNames:      []string{"raspberrypi", "pi"},
		MACOUIPrefixes: []string{"b8:27:eb", "dc:a6:32", "e4:5f:01"},
	},
	{
		Token:       "hass",
		DisplayName: "Home Assistant",
		Ports:       []int{8123},
		MDNSNames:   []string{"homeassistant", "hass"},
	},
	// Networking & Infrastructure
	{
		Token:          "rtr",
		DisplayName:    "Router",
		Ports:          []int{80, 443, 22},
		MDNSNames:      []string{"fritzbox", "fritz.box", "openwrt", "router", "pfsense", "opnsense", "gateway"},
		MACOUIPrefixes: []string{"3c:a6:2f", "00:0d:b9", "d8:ec:5e"}, // FritzBox, PC Engines APU, TP-Link
	},
	{
		Token:          "unf",
		DisplayName:    "UniFi",
		Ports:          []int{8443, 8080},
		MDNSNames:      []string{"unifi", "controller", "unifi-controller"},
		MACOUIPrefixes: []string{"04:18:d6", "74:83:c2", "fc:ec:da"}, // Ubiquiti OUIs
	},
	{
		Token:          "dns",
		DisplayName:    "DNS / AdBlock",
		Ports:          []int{53, 80, 443, 3000},
		MDNSNames:      []string{"pihole", "adguard", "dns", "dnsmasq"},
		MACOUIPrefixes: []string{"b8:27:eb"}, // Frequently hosted on Raspberry Pi
	},
	{
		Token:       "rpx",
		DisplayName: "Rev. Proxy",
		Ports:       []int{80, 443, 81, 8080},
		MDNSNames:   []string{"nginx", "npm", "traefik", "caddy", "proxy", "haproxy"},
	},
	{
		Token:       "vpn",
		DisplayName: "VPN",
		Ports:       []int{1194, 51820},
		MDNSNames:   []string{"vpn", "wireguard", "openvpn", "tailscale", "headscale"},
	},
	// Databases
	{
		Token:       "pgs",
		DisplayName: "PostgreSQL",
		Ports:       []int{5432},
	},
	{
		Token:       "mys",
		DisplayName: "MySQL",
		Ports:       []int{3306},
	},
	{
		Token:       "rds",
		DisplayName: "Redis",
		Ports:       []int{6379},
	},
	{
		Token:       "mgo",
		DisplayName: "MongoDB",
		Ports:       []int{27017},
	},
	{
		Token:       "els",
		DisplayName: "Elasticsearch",
		Ports:       []int{9200},
	},
	// Virtualization & Cloud-Native
	{
		Token:       "k8s",
		DisplayName: "Kubernetes",
		Ports:       []int{6443},
		MDNSNames:   []string{"k8s", "kubernetes", "k3s", "rancher"},
	},
	{
		Token:       "dck",
		DisplayName: "Docker",
		Ports:       []int{2375, 2376},
		MDNSNames:   []string{"docker", "dck"},
	},
	{
		Token:       "pbs",
		DisplayName: "PVE Backup",
		Ports:       []int{8007},
		MDNSNames:   []string{"pbs", "proxmox-backup"},
	},
	{
		Token:       "pmg",
		DisplayName: "PVE Mail GW",
		Ports:       []int{8006},
		MDNSNames:   []string{"pmg", "proxmox-mail-gateway"},
	},
	{
		Token:       "vwr",
		DisplayName: "VMware ESXi",
		Ports:       []int{443, 902},
		MDNSNames:   []string{"esxi", "vmware", "vcenter", "vsphere"},
	},
	{
		Token:       "xcp",
		DisplayName: "XCP-ng",
		Ports:       []int{80, 443},
		MDNSNames:   []string{"xcp", "xcp-ng", "xen", "xenserver"},
	},
	{
		Token:       "hvs",
		DisplayName: "Hyper-V",
		Ports:       []int{5985, 5986, 3389},
		MDNSNames:   []string{"hyperv", "windows-server", "rdp"},
	},
	// Media & Homelab services
	{
		Token:       "plx",
		DisplayName: "Plex",
		Ports:       []int{32400},
		MDNSNames:   []string{"plex", "plex-media-server"},
	},
	{
		Token:       "jly",
		DisplayName: "Jellyfin",
		Ports:       []int{8096, 8920},
		MDNSNames:   []string{"jellyfin", "jly"},
	},
	{
		Token:       "pot",
		DisplayName: "Portainer",
		Ports:       []int{9000, 9443},
		MDNSNames:   []string{"portainer", "pot"},
	},
	{
		Token:       "mio",
		DisplayName: "MinIO",
		Ports:       []int{9000, 9001},
		MDNSNames:   []string{"minio", "s3", "object-storage"},
	},
	{
		Token:       "git",
		DisplayName: "Git Server",
		Ports:       []int{22, 80, 443, 3000},
		MDNSNames:   []string{"gitlab", "gitea", "forgejo", "git-server"},
	},
	{
		Token:       "mon",
		DisplayName: "Monitoring",
		Ports:       []int{3000, 9090, 9100},
		MDNSNames:   []string{"grafana", "prometheus", "monitoring", "node-exporter", "netdata"},
	},
	{
		Token:       "emx",
		DisplayName: "MQTT",
		Ports:       []int{1883, 8883, 18083},
		MDNSNames:   []string{"emqx", "mqtt", "mosquitto", "broker"},
	},
	{
		Token:       "n8n",
		DisplayName: "n8n",
		Ports:       []int{5678},
		MDNSNames:   []string{"n8n", "automation", "workflow"},
	},
	{
		Token:       "hom",
		DisplayName: "Dashboard",
		Ports:       []int{80, 443},
		MDNSNames:   []string{"homer", "dashboard", "homepage", "heimdall"},
	},
	{
		Token:       "fdy",
		DisplayName: "Foundry VTT",
		Ports:       []int{30000, 80, 443, 8080, 8443},
		MDNSNames:   []string{"foundry", "foundryvtt", "vtt"},
	},
	{
		Token:       "owu",
		DisplayName: "Open WebUI",
		Ports:       []int{8080, 3000, 80, 443},
		MDNSNames:   []string{"openwebui", "open-webui", "ollama-webui"},
	},
	{
		Token:       "ncd",
		DisplayName: "Nextcloud",
		Ports:       []int{80, 443, 8080},
		MDNSNames:   []string{"nextcloud"},
	},
	{
		Token:       "ppl",
		DisplayName: "Paperless",
		Ports:       []int{8000, 8010, 80, 443},
		MDNSNames:   []string{"paperless", "paperless-ngx"},
	},
	// Storage & Directories
	{
		Token:       "smb",
		DisplayName: "Samba",
		Ports:       []int{445, 139},
		MDNSNames:   []string{"samba", "active-directory", "domain-controller", "smb"},
	},
	{
		Token:       "nfs",
		DisplayName: "NFS",
		Ports:       []int{2049},
		MDNSNames:   []string{"nfs", "nfs-server"},
	},
	{
		Token:       "ldp",
		DisplayName: "LDAP",
		Ports:       []int{389, 636},
		MDNSNames:   []string{"ldap", "openldap", "active-directory-ldap"},
	},
	{
		Token:       "val",
		DisplayName: "Vault",
		Ports:       []int{8200},
		MDNSNames:   []string{"vault", "hashicorp-vault"},
	},
	// Smart Home & Hardware Devices
	{
		Token:          "apc",
		DisplayName:    "USV",
		Ports:          []int{80, 443, 161},
		MDNSNames:      []string{"apc", "ups", "smart-ups", "network-management-card"},
		MACOUIPrefixes: []string{"00:c0:b7"}, // APC OUI
	},
	{
		Token:          "prt",
		DisplayName:    "Drucker",
		Ports:          []int{9100, 631, 80},
		MDNSNames:      []string{"printer", "hp", "canon", "epson", "lexmark", "brother"},
		MACOUIPrefixes: []string{"00:18:71", "00:26:ab", "00:00:85", "00:20:c5"}, // HP, Canon, Epson OUIs
	},
	{
		Token:          "kam",
		DisplayName:    "IP-Kamera",
		Ports:          []int{80, 443, 554, 8000},
		MDNSNames:      []string{"camera", "cam", "nvr", "ip-camera", "synology-camera"},
		MACOUIPrefixes: []string{"00:1a:07", "00:40:8c", "00:0f:7c"}, // Hikvision, Axis, Dahua OUIs
	},
	{
		Token:          "swc",
		DisplayName:    "Switch",
		Ports:          []int{80, 443, 22, 23},
		MDNSNames:      []string{"switch", "managed-switch", "cisco", "netgear", "tp-link-switch"},
		MACOUIPrefixes: []string{"00:10:e0", "00:26:99", "00:1b:2f", "00:14:d4"}, // Cisco, Netgear, TP-Link OUIs
	},
	{
		Token:          "iot",
		DisplayName:    "IoT / ESP",
		Ports:          []int{80, 1883},
		MDNSNames:      []string{"shelly", "sonoff", "iot-device", "esp32", "esp8266"},
		MACOUIPrefixes: []string{"84:0d:8e", "24:0a:c4", "30:ae:a4"}, // Espressif OUIs (ESP8266/ESP32)
	},
}

// FindSignature retrieves the signature for a given token.
func FindSignature(token string) (ServiceSignature, bool) {
	for _, sig := range Signatures {
		if sig.Token == token {
			return sig, true
		}
	}
	return ServiceSignature{}, false
}

// isAmbiguousPort returns true if a port is too generic to identify a service by itself.
// These ports are shared by many services (webservers, SSH, DNS, alt-HTTP...) and require
// additional evidence (OUI, mDNS, or payload fingerprint) for reliable identification.
func isAmbiguousPort(port int) bool {
	switch port {
	case 22, 23, 53, 80, 139, 161, 443, 445, // Standard protocols
		631,  // IPP (printers, but also CUPS on any Linux)
		1883, // MQTT (shared by many IoT platforms)
		3000, // Grafana, Gitea, AdGuard, n8n, Rails...
		8080, // Common alt-HTTP (used by dozens of services)
		8443, // Common alt-HTTPS (UniFi, Traefik, Jenkins...)
		9000, // Portainer, MinIO, SonarQube, PHP-FPM...
		9001: // MinIO Console, Supervisor, Mesos...
		return true
	}
	return false
}
