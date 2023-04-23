package chat

// User represents a chat user.
type User struct {
	Name       string `json:"name"`
	Network    string `json:"network"`
	Host       string `json:"host"`
	ServerPort int64  `json:"serverPort"` // depends on the network
	NotifyPort int64  `json:"notifyPort"` // always TCP
}
