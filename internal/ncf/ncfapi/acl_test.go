package ncfapi

import "testing"

func intp(n int) *int { return &n }

// A rule's ranges mean the same to every consumer: a missing end takes the
// full span's, a protocol range covering 0-255 is every protocol, and a port
// range covering 0-65535 restricts nothing.
func TestRuleRanges(t *testing.T) {
	for name, tc := range map[string]struct {
		r      *Range
		proto  Span
		protOK bool
		port   Span
		portOK bool
	}{
		"absent":        {nil, Span{}, false, Span{}, false},
		"empty":         {&Range{}, Span{}, false, Span{}, false},
		"single":        {&Range{Min: intp(53), Max: intp(53)}, Span{53, 53}, true, Span{53, 53}, true},
		"only a min":    {&Range{Min: intp(6)}, Span{6, 255}, true, Span{6, 65535}, true},
		"only a max":    {&Range{Max: intp(17)}, Span{0, 17}, true, Span{0, 17}, true},
		"every value":   {&Range{Min: intp(0), Max: intp(255)}, AllProtocols, true, Span{0, 255}, true},
		"every port":    {&Range{Min: intp(0), Max: intp(65535)}, Span{0, 65535}, true, Span{}, false},
		"port, no ends": {&Range{Min: intp(0)}, Span{0, 255}, true, Span{}, false},
	} {
		p := &ACLParsed{Protocol: tc.r, TCP: &PortRange{SourcePort: tc.r, DestinationPort: tc.r}}
		if s, ok := p.Protocols(); s != tc.proto || ok != tc.protOK {
			t.Errorf("%s: Protocols() = %v, %v", name, s, ok)
		}
		if s, ok := p.TCP.SourcePorts(); s != tc.port || ok != tc.portOK {
			t.Errorf("%s: SourcePorts() = %v, %v", name, s, ok)
		}
		if s, ok := p.TCP.DestinationPorts(); s != tc.port || ok != tc.portOK {
			t.Errorf("%s: DestinationPorts() = %v, %v", name, s, ok)
		}
	}
	// A nil port pair (no tcp or udp section) restricts nothing.
	var none *PortRange
	if _, ok := none.SourcePorts(); ok {
		t.Error("nil PortRange restricts source ports")
	}
	if _, ok := (*ACLParsed)(nil).Protocols(); ok {
		t.Error("nil ACLParsed gives a protocol")
	}
}
