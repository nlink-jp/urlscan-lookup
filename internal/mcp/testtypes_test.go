package mcp

import "encoding/json"

// rpcError is a JSON-RPC error object as the tests read it.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// response is a JSON-RPC answer as the tests read it.
type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}
