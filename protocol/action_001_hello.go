package protocol

// HelloRequest is the request sent by the client to the server to keep the
// connection alive.
type HelloRequest struct {
	RequestCommon
}

// NewHelloRequest creates a new HelloRequest.
func NewHelloRequest() HelloRequest {
	return HelloRequest{
		RequestCommon: RequestCommon{
			version: Version1,
			action:  ActionHello,
		},
	}
}

// HelloResponse is the response sent by the server to the client acknowledging
// that everything is fine.
type HelloResponse struct {
	ResponseCommon
}

// NewHelloResponse creates a new NewHelloResponse.
func NewHelloResponse() HelloResponse {
	return HelloResponse{
		ResponseCommon: ResponseCommon{
			success: true,
		},
	}
}
