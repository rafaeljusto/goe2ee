# Chat

When talking about end-to-end encryption a chat solution is something that
usually comes into discussion. For this reason, this example illustrates how a
chat application would work using goe2ee.

```mermaid
graph TD;
UserA<==>Registry
UserB<==>Registry
UserC<==>Registry
UserA--tcp-->UserB
UserC--tcp-->UserB
UserB--udp-->UserA
UserC--udp-->UserA
UserA--tcp-->UserC
UserB--tcp-->UserC
```

A central registry will be responsible for registering all users from the chat
room, and notifying their peers that some users joined or left the chat. That
means that each user will start a goe2ee and an HTTP server, where the HTTP
server will be used to receive notifications from the registry. Users can
connect using the goe2ee protocol via UDP or TCP (each user decides
independently).

```mermaid
sequenceDiagram
activate user
user-->>user: start goe2ee server
user-->>user: start HTTP server
user->>registry: register me
activate registry
registry-->>registry: store new user data
loop every registeredUser
  registry--)registeredUser: notify user joined
  activate registeredUser
  registeredUser--)user: connect with goe2ee
  deactivate registeredUser
end
registry-->>user: ok
deactivate registry
loop every chat message
  registeredUser->>user: chat message
end
user->>registry: remove me
activate registry
loop every registeredUser
  registry--)registeredUser: notify user left
end
registry-->>user: ok
deactivate registry
deactivate user
```

The chat conversation will be automatically generated using the [Excuser
API](https://excuser-three.vercel.app/), randomly generating messages between 1
and 10 seconds. All messages are sent to all registered users, so it behaves
like a chat room/group. The client won't wait for a response from the server.

To execute this example you can first run the registry:
```shell
go run cmd/registry/main.go
```

That will print the registry address, then in other terminal tabs you can run as
many users as you would like:
```shell
go run cmd/user/main.go -name <name> -registry <registry-address> -network <network>
```

For example, running a TCP user:
```shell
go run cmd/user/main.go -name Rafael -registry localhost:62465 -network tcp
```
and a UDP user:
```shell
go run cmd/user/main.go -name James -registry localhost:62465 -network udp
```

![goe2ee-chat](https://github.com/rafaeljusto/goe2ee/assets/611469/57822368-7df5-49c4-9c18-6662c178778d)
