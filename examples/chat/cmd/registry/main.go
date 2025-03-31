package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/rafaeljusto/goe2ee/examples/chat"
)

var usersStore sync.Map

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("error creating listener: %v", err)
	}

	var server http.Server
	http.Handle("/users", http.HandlerFunc(usersHandler))
	http.Handle("/users/", http.HandlerFunc(usersHandler))

	go func() {
		if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server closing error: %v", err)
		}
	}()

	log.Printf("server listening on %s", listener.Addr())

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	shutdownCtx, shutdownRelease := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownRelease()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("http shutdown error: %v", err)
	}
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		var users []chat.User
		usersStore.Range(func(_, value any) bool {
			users = append(users, value.(chat.User))
			return true
		})
		if err := json.NewEncoder(w).Encode(users); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	case http.MethodPost:
		var user chat.User
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var abort bool
		usersStore.Range(func(key, _ any) bool {
			if key == user.Name {
				http.Error(w, "user already exists", http.StatusConflict)
				abort = true
				return false
			}
			return true
		})
		if abort {
			return
		}
		usersStore.Store(user.Name, user)
		w.WriteHeader(http.StatusCreated)
		notification := chat.Notification{
			Event: chat.NotificationEventUserJoined,
			User:  user,
		}
		usersStore.Range(func(key, existingUserRaw any) bool {
			if key != user.Name {
				existingUser := existingUserRaw.(chat.User)
				if err := notification.Notify(existingUser.Host, existingUser.NotifyPort); err != nil {
					log.Printf("error notifying user '%s': %v", key, err)
				}
				// notify the new user about the existing ones
				existingNotification := chat.Notification{
					Event: chat.NotificationEventUserJoined,
					User:  existingUser,
				}
				if err := existingNotification.Notify(user.Host, user.NotifyPort); err != nil {
					log.Printf("error notifying joined user '%s': %v", user.Name, err)
				}
			}
			return true
		})
		log.Printf("user '%s' joined", user.Name)
	case http.MethodDelete:
		userName := r.URL.Path[len("/users/"):]
		userRaw, ok := usersStore.Load(userName)
		if !ok {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		user := userRaw.(chat.User)
		usersStore.Delete(userName)
		w.WriteHeader(http.StatusNoContent)
		notification := chat.Notification{
			Event: chat.NotificationEventUserLeft,
			User:  user,
		}
		usersStore.Range(func(key, userRaw any) bool {
			user := userRaw.(chat.User)
			if err := notification.Notify(user.Host, user.NotifyPort); err != nil {
				log.Printf("error notifying user '%s': %v", key, err)
			}
			return true
		})
		log.Printf("user '%s' left", userName)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
