package apoch

import (
	"net"

	"github.com/projectdiscovery/gologger/levels"
)

// Resource represents an AWS resource
type Resource struct {
	ID               string
	PublicIP         net.IP
	Type             string
	AvailabilityZone string
	Region           string
	Account          string
}

// discardWriter is a Writer on which all Write calls succeed without doing anything.
type discardWriter struct{}

func (w discardWriter) Write(_ []byte, _ levels.Level) {
	// ignore / discard
}
