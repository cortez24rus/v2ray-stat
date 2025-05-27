package config

type Client struct {
	Email    string `json:"email"`
	ID       string `json:"id,omitempty"`
	Password string `json:"password,omitempty"`
}

type InboundSettings struct {
	Clients    []Client `json:"clients"`
	Decryption *string  `json:"decryption,omitempty"`
	Address    *string  `json:"address,omitempty"`
}

type XrayInbound struct {
	Tag            string          `json:"tag"`
	Settings       InboundSettings `json:"settings"`
	Port           int             `json:"port"`
	Protocol       string          `json:"protocol"`
	Listen         string          `json:"listen"`
	StreamSettings map[string]any  `json:"streamSettings,omitempty"`
	Sniffing       map[string]any  `json:"sniffing,omitempty"`
	Allocate       map[string]any  `json:"allocate,omitempty"`
}

type ConfigXray struct {
	Remarks          string           `json:"remarks,omitempty"`
	Log              map[string]any   `json:"log"`
	Dns              map[string]any   `json:"dns"`
	Routing          map[string]any   `json:"routing"`
	Inbounds         []XrayInbound    `json:"inbounds"`
	Outbounds        []map[string]any `json:"outbounds"`
	Policy           map[string]any   `json:"policy"`
	API              map[string]any   `json:"api"`
	Stats            map[string]any   `json:"stats"`
	FakeDNS          []map[string]any `json:"fakedns"`
	Reverse          map[string]any   `json:"reverse"`
	Transport        map[string]any   `json:"transport,omitempty"`
	Observatory      map[string]any   `json:"observatory,omitempty"`
	BurstObservatory map[string]any   `json:"burstObservatory,omitempty"`
}

type SingBoxUser struct {
	Name     string `json:"name"`
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
}

type SingBoxInbound struct {
	Type       string         `json:"type"`
	Tag        string         `json:"tag"`
	Listen     string         `json:"listen"`
	ListenPort int            `json:"listen_port"`
	Users      []SingBoxUser  `json:"users"`
	Transport  map[string]any `json:"transport,omitempty"`
	Multiplex  map[string]any `json:"multiplex,omitempty"`
}

type ConfigSingBox struct {
	Log          map[string]any   `json:"log"`
	Dns          map[string]any   `json:"dns"`
	Inbounds     []SingBoxInbound `json:"inbounds"`
	Outbounds    []map[string]any `json:"outbounds"`
	Route        map[string]any   `json:"route"`
	Experimental map[string]any   `json:"experimental,omitempty"`
}
