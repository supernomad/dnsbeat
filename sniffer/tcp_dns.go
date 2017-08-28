package sniffer

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Gopacket doesn't provide direct support for DNS over TCP, see https://github.com/google/gopacket/issues/236
type tcpDNS struct {
	TCP layers.TCP
}

func (m *tcpDNS) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	return m.TCP.DecodeFromBytes(data, df)
}

func (m *tcpDNS) CanDecode() gopacket.LayerClass { return m.TCP.CanDecode() }

// Determine if a TCP segment contains a full DNS message (i.e. not fragmented)
func (m *tcpDNS) hasSelfContainedDNSPayload() bool {
	payload := m.TCP.LayerPayload()
	if len(payload) < 2 {
		return false
	}

	// Assume it's a self-contained DNS message if the Length field
	// matches the length of the TCP segment
	dnsLengthField := binary.BigEndian.Uint16(payload)
	return int(dnsLengthField) == len(payload)-2
}

func (m *tcpDNS) NextLayerType() gopacket.LayerType {
	// TODO: deal with TCP fragmentation and out-of-order segments
	if (m.TCP.SrcPort == 53 || m.TCP.DstPort == 53) && m.hasSelfContainedDNSPayload() {
		return layers.LayerTypeDNS
	}
	return m.TCP.NextLayerType()
}

func (m *tcpDNS) LayerPayload() []byte {
	payload := m.TCP.LayerPayload()
	if len(payload) > 1 && (m.TCP.SrcPort == 53 || m.TCP.DstPort == 53) {
		// Omit the DNS length field, only included
		// in TCP, in order to reuse the DNS UDP parser
		payload = payload[2:]
	}
	return payload
}
