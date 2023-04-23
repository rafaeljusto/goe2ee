package chat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Registry represents a service registry.
type Registry struct {
	host string
}

// NewRegistry creates a new service registry.
func NewRegistry(host string) *Registry {
	return &Registry{
		host: host,
	}
}

// Register registers a new user in the service registry.
func (r Registry) Register(user User) (err error) {
	var body bytes.Buffer
	if err = json.NewEncoder(&body).Encode(user); err != nil {
		return
	}
	var response *http.Response
	response, err = http.Post("http://"+r.host+"/users", "application/json", &body)
	if err != nil {
		return
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	if response.StatusCode != http.StatusCreated {
		err = fmt.Errorf("unexpected error response: %s", response.Status)
		return
	}
	return
}

// Unregister unregisters a user from the service registry.
func (r Registry) Unregister(userName string) (err error) {
	var request *http.Request
	request, err = http.NewRequest(http.MethodDelete, "http://"+r.host+"/users/"+userName, nil)
	if err != nil {
		return
	}
	var response *http.Response
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		return
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	if response.StatusCode != http.StatusNoContent {
		err = fmt.Errorf("unexpected error response: %s", response.Status)
		return
	}
	return
}

// Host returns the host of the service registry.
func (r Registry) Host() string {
	return r.host
}
