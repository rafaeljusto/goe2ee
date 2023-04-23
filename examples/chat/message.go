package chat

import (
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const messageColorReset = "\033[0m"

var messageColors = []string{
	"\033[31m", // Red
	"\033[32m", // Green
	"\033[33m", // Yellow
	"\033[34m", // Blue
	"\033[35m", // Purple
	"\033[36m", // Cyan
	"\033[37m", // Gray
	"\033[97m", // White
}

// Message represents a chat message.
type Message struct {
	System  bool   `json:"-"` // used for internal messages
	From    User   `json:"from"`
	Content string `json:"content"`
}

// GenerateMessage creates a new message using the Excuser API [1].
//
// [1] https://excuser-three.vercel.app/
func GenerateMessage(from User) (msg *Message, err error) {
	var response *http.Response
	response, err = http.Get("https://excuser-three.vercel.app/v1/excuse/")
	if err != nil {
		return
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	var excuses []struct {
		Excuse string `json:"excuse"`
	}
	if err = json.NewDecoder(response.Body).Decode(&excuses); err != nil {
		return
	}
	if len(excuses) == 0 {
		err = errors.New("no excuses found")
		return
	}
	msg = &Message{
		From:    from,
		Content: excuses[0].Excuse,
	}
	return
}

// Color returns a color for the message. It should use the same color for the
// same user (host + name).
func (m Message) color() string {
	hash := sha512.New()
	_, _ = hash.Write([]byte(m.From.Host))
	_, _ = hash.Write([]byte(m.From.Name))
	hashed := hash.Sum(nil)
	var sum int
	for _, b := range hashed {
		sum += int(b)
	}
	return messageColors[sum%len(messageColors)]
}

// String returns a string representation of the message.
func (m Message) String() string {
	if m.System {
		m.From.Name = "🤖"
	}
	return fmt.Sprintf("%s %s[%s] %s%s",
		time.Now().Format(time.RFC3339), m.color(), m.From.Name, m.Content, messageColorReset)
}
