package chat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// NotificationEvent represents the type of event that happened.
type NotificationEvent string

// List of possible notification events.
const (
	NotificationEventUserJoined NotificationEvent = "userJoined"
	NotificationEventUserLeft   NotificationEvent = "userLeft"
)

// Notification represents a notification sent by the service registry.
type Notification struct {
	Event NotificationEvent `json:"event"`
	User  User              `json:"user"`
}

// Notify sends a notification to a user.
func (n Notification) Notify(host string, port int64) (err error) {
	url := "http://" + host + ":" + strconv.FormatInt(port, 10) + "/notify"
	var body bytes.Buffer
	if err = json.NewEncoder(&body).Encode(n); err != nil {
		err = fmt.Errorf("error encoding notification: %w", err)
		return
	}
	var response *http.Response
	response, err = http.Post(url, "application/json", &body)
	if err != nil {
		err = fmt.Errorf("error notifying user: %w", err)
		return
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	if response.StatusCode != http.StatusOK {
		var responseBody []byte
		responseBody, err = io.ReadAll(response.Body)
		if err != nil {
			err = fmt.Errorf("unexpected error response: %s", response.Status)
		} else {
			err = fmt.Errorf("unexpected error response: %s → %s", response.Status, responseBody)
		}
	}
	return
}
