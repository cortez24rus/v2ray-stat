package config

type DisabledUsersConfigSingbox struct {
	Inbounds []SingboxInbound `json:"inbounds"`
}

type SingboxClient struct {
	Name     string `json:"name"`
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
}

type SingboxInbound struct {
	Type       string          `json:"type"`
	Tag        string          `json:"tag"`
	Listen     string          `json:"listen"`
	ListenPort int             `json:"listen_port"`
	Users      []SingboxClient `json:"users"`
	Transport  map[string]any  `json:"transport,omitempty"`
	Multiplex  map[string]any  `json:"multiplex,omitempty"`
}

type ConfigSingbox struct {
	Log          map[string]any   `json:"log"`
	Dns          map[string]any   `json:"dns"`
	Inbounds     []SingboxInbound `json:"inbounds"`
	Outbounds    []map[string]any `json:"outbounds"`
	Route        map[string]any   `json:"route"`
	Experimental map[string]any   `json:"experimental,omitempty"`
}
