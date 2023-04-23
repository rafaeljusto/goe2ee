package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/rafaeljusto/goe2ee"
	"github.com/rafaeljusto/goe2ee/examples/chat"
	"github.com/rafaeljusto/goe2ee/key"
	"github.com/rafaeljusto/goe2ee/protocol"
)

func main() {
	name := flag.String("name", "", "user name")
	port := flag.Int("port", 0, "server port")
	network := flag.String("network", "tcp", "network protocol")
	registryHost := flag.String("registry", "", "service registry address")
	flag.Parse()

	if name == nil || *name == "" {
		log.Fatal("name is required")
	}
	if registryHost == nil || *registryHost == "" {
		log.Fatal("service registry address is required")
	}

	service := newService(chat.User{
		Name: *name,
	}, chat.NewRegistry(*registryHost))

	serverKeyManager, err := key.ServerManagerGenerateOnTheFly(protocol.KeyAlgorithmECDSA)
	if err != nil {
		log.Println(err)
		return
	}

	server := goe2ee.NewServer(
		goe2ee.ServerHandlerFunc(service.handleMessage),
		goe2ee.ServerWithKeyManager(serverKeyManager),
		goe2ee.ServerWithWriteTimeout(0), // don't timeout
		goe2ee.ServerWithReadTimeout(0),  // don't timeout
		goe2ee.ServerWithLogger(log.New(io.Discard, "", 0)),
	)
	defer func() {
		if err := server.Close(); err != nil {
			log.Println(err)
		}
	}()

	var addr net.Addr
	switch *network {
	case "tcp":
		addr, err = server.StartTCP("127.0.0.1:" + strconv.FormatInt(int64(*port), 10))
		if err != nil {
			log.Println(err)
			return
		}
		service.user.Network = "tcp"
	case "udp":
		addr, err = server.StartUDP("127.0.0.1:" + strconv.FormatInt(int64(*port), 10))
		if err != nil {
			log.Println(err)
			return
		}
		service.user.Network = "udp"
	default:
		log.Printf("network %q not supported", *network)
		return
	}
	fmt.Printf("goe2ee server listening on %s\n", addr.String())

	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		log.Println(err)
		return
	}
	service.user.Host = host
	service.user.ServerPort, err = strconv.ParseInt(portStr, 10, 64)
	if err != nil {
		log.Println(err)
		return
	}

	notifyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Println(err)
		return
	}
	var notifyServer http.Server
	http.Handle("/notify", http.HandlerFunc(service.handleNotification))
	go func() {
		if err := notifyServer.Serve(notifyListener); !errors.Is(err, http.ErrServerClosed) {
			log.Printf("notify server closing error: %v", err)
		}
	}()
	defer func() {
		shutdownCtx, shutdownRelease := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownRelease()

		if err := notifyServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("notify server shutdown error: %v", err)
		}
	}()
	fmt.Printf("notification server listening on %s\n", notifyListener.Addr())

	_, portStr, err = net.SplitHostPort(notifyListener.Addr().String())
	if err != nil {
		log.Println(err)
		return
	}
	service.user.NotifyPort, err = strconv.ParseInt(portStr, 10, 64)
	if err != nil {
		log.Println(err)
		return
	}

	go service.printer()

	if err := service.registry.Register(service.user); err != nil {
		log.Println(err)
		return
	}
	defer func() {
		if err := service.registry.Unregister(service.user.Name); err != nil {
			log.Println(err)
		}
	}()

	go service.startChatting()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	close(service.stop)
}

type service struct {
	user            chat.User
	otherUsers      map[string]userConnection
	otherUsersMutex sync.RWMutex
	registry        *chat.Registry
	incoming        chan chat.Message
	stop            chan struct{}
}

func newService(user chat.User, registry *chat.Registry) *service {
	return &service{
		user:       user,
		otherUsers: make(map[string]userConnection),
		registry:   registry,
		incoming:   make(chan chat.Message),
		stop:       make(chan struct{}),
	}
}

func (s *service) handleMessage(w io.Writer, r io.Reader, remoteAddr net.Addr) error {
	var message chat.Message
	if err := json.NewDecoder(r).Decode(&message); err != nil {
		return err
	}
	s.incoming <- message
	_, err := w.Write([]byte("ok"))
	return err
}

func (s *service) handleNotification(w http.ResponseWriter, r *http.Request) {
	var notification chat.Notification
	if err := json.NewDecoder(r.Body).Decode(&notification); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch notification.Event {
	case chat.NotificationEventUserJoined:
		var conn net.Conn
		hostport := notification.User.Host + ":" + strconv.FormatInt(notification.User.ServerPort, 10)

		switch notification.User.Network {
		case "tcp":
			var err error
			conn, err = goe2ee.DialTCP(hostport,
				goe2ee.ClientWithKeepAlive(true),
				goe2ee.ClientWithKeyFetcher(key.NewClientFetcherCache(
					key.NewClientFetcherProtocol(notification.User.Network, hostport),
					key.ClientFetcherCacheWithTTL(0), // don't expire cache
				)),
				goe2ee.ClientWithWriteTimeout(0), // don't timeout
				goe2ee.ClientWithReadTimeout(0),  // don't timeout
				goe2ee.ClientWithExpectReply(false),
			)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		case "udp":
			var err error
			conn, err = goe2ee.DialUDP(hostport,
				goe2ee.ClientWithKeepAlive(true),
				goe2ee.ClientWithKeyFetcher(key.NewClientFetcherCache(
					key.NewClientFetcherProtocol(notification.User.Network, hostport),
					key.ClientFetcherCacheWithTTL(0), // don't expire cache
				)),
				goe2ee.ClientWithWriteTimeout(0), // don't timeout
				goe2ee.ClientWithReadTimeout(0),  // don't timeout
				goe2ee.ClientWithExpectReply(false),
			)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		default:
			http.Error(w, "invalid network "+notification.User.Network, http.StatusInternalServerError)
		}

		s.otherUsersMutex.Lock()
		s.otherUsers[notification.User.Name] = userConnection{
			user: notification.User,
			conn: conn,
		}
		s.otherUsersMutex.Unlock()

		s.incoming <- chat.Message{
			System:  true,
			Content: fmt.Sprintf("%s joined the chat", notification.User.Name),
		}
	case chat.NotificationEventUserLeft:
		s.otherUsersMutex.Lock()
		if conn, ok := s.otherUsers[notification.User.Name]; ok {
			if err := conn.conn.Close(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
		delete(s.otherUsers, notification.User.Name)
		s.otherUsersMutex.Unlock()

		s.incoming <- chat.Message{
			System:  true,
			Content: fmt.Sprintf("%s left the chat", notification.User.Name),
		}
	}
}

func (s *service) startChatting() {
	ticker := time.NewTicker(time.Duration(rand.Intn(10)+1) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ticker.Reset(time.Duration(rand.Intn(10)+1) * time.Second)
		case <-s.stop:
			return
		}

		s.otherUsersMutex.RLock()
		if len(s.otherUsers) == 0 {
			s.otherUsersMutex.RUnlock()
			continue
		}
		s.otherUsersMutex.RUnlock()

		message, err := chat.GenerateMessage(s.user)
		if err != nil {
			continue
		}

		s.otherUsersMutex.RLock()
		for _, userConn := range s.otherUsers {
			if err = json.NewEncoder(userConn.conn).Encode(message); err != nil {
				log.Println(err)
			}
		}
		s.otherUsersMutex.RUnlock()

		s.incoming <- *message
	}
}

func (s *service) printer() {
	for {
		select {
		case <-s.stop:
			return
		case message := <-s.incoming:
			if message.From.Name == "" {
				message.From = s.user
			}
			fmt.Println(message)
		}
	}
}

type userConnection struct {
	user chat.User
	conn net.Conn
}
