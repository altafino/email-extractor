package oauth2

import (
	"github.com/emersion/go-sasl"
)

// NewXOAUTH2Client creates a new SASL client for XOAUTH2 authentication
func NewXOAUTH2Client(username, token string) sasl.Client {
	// Create a custom XOAUTH2 client since the function name has changed
	// or might not be available in the current version
	return &xoauth2Client{
		username: username,
		token:    token,
	}
}

// xoauth2Client implements the XOAUTH2 SASL mechanism
type xoauth2Client struct {
	username string
	token    string
}

// Start begins the SASL exchange
func (a *xoauth2Client) Start() (mech string, ir []byte, err error) {
	mech = "XOAUTH2"
	
	// Format: "user=<username>\x01auth=Bearer <token>\x01\x01"
	ir = []byte("user=" + a.username + "\x01auth=Bearer " + a.token + "\x01\x01")
	
	return
}

// Next continues the SASL exchange
func (a *xoauth2Client) Next(challenge []byte) ([]byte, error) {
	// XOAUTH2 is a single round-trip mechanism, so we should never get here
	return nil, sasl.ErrUnexpectedServerChallenge
}

// For reference, this is how the XOAUTH2 mechanism works:
// 1. Client sends: "user=<username>\x01auth=Bearer <token>\x01\x01"
// 2. Server responds with success or failure 