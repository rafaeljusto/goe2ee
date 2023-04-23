package protocol

// Action is the type of action to be performed by the client/server.
type Action uint8

// List of possible actions.
const (
	ActionHello    Action = 0x1
	ActionSetup    Action = 0x2
	ActionProcess  Action = 0x3
	ActionFetchKey Action = 0x4
)

// String returns the string representation of the action.
func (a Action) String() string {
	switch a {
	case ActionHello:
		return "Hello"
	case ActionSetup:
		return "Setup"
	case ActionProcess:
		return "Process"
	case ActionFetchKey:
		return "FetchKey"
	default:
		return "Unknown"
	}
}
