package api

type Stat struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ApiResponse struct {
	Stat []Stat `json:"stat"`
}
