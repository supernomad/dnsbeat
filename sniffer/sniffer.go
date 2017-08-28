package sniffer

import (
	"errors"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

// Packet represents a sniffed packet
type Packet struct {
	Proto string

	SrcIP   net.IP
	SrcPort uint16

	DstIP   net.IP
	DstPort uint16

	DNS layers.DNS
}

var (
	eth layers.Ethernet
	ip4 layers.IPv4
	ip6 layers.IPv6
	tcp tcpDNS
	udp layers.UDP
)

// Sniffer is a struct representing a network sniffer the exports packets that match a specific BPF rule.
type Sniffer struct {
	tpkt    *afpacket.TPacket
	stop    chan struct{}
	Packets chan *Packet
}

func parse(packetData []byte) (*Packet, error) {
	pkt := &Packet{}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &udp, &tcp, &pkt.DNS)
	decoded := []gopacket.LayerType{}

	err := parser.DecodeLayers(packetData, &decoded)
	if err != nil {
		return nil, err
	}

	good := false
	for _, layerType := range decoded {
		switch layerType {
		case layers.LayerTypeIPv4:
			pkt.SrcIP = ip4.SrcIP
			pkt.DstIP = ip4.DstIP
		case layers.LayerTypeIPv6:
			pkt.SrcIP = ip6.SrcIP
			pkt.DstIP = ip6.DstIP
		case layers.LayerTypeTCP:
			pkt.Proto = "tcp"
			pkt.SrcPort = uint16(tcp.TCP.SrcPort)
			pkt.DstPort = uint16(tcp.TCP.DstPort)
		case layers.LayerTypeUDP:
			pkt.Proto = "udp"
			pkt.SrcPort = uint16(udp.SrcPort)
			pkt.DstPort = uint16(udp.DstPort)
		case layers.LayerTypeDNS:
			good = true
		}
	}

	if !good {
		return nil, errors.New("not a DNS packet")
	}
	return pkt, nil
}

func (s *Sniffer) pipeline() {
loop:
	for {
		select {
		case <-s.stop:
			break loop
		default:
			packetData, _, err := s.tpkt.ZeroCopyReadPacketData()
			if err != nil {
				continue
			}
			pkt, err := parse(packetData)
			if err != nil {
				continue
			}
			s.Packets <- pkt
		}
	}
	close(s.stop)
}

func (s *Sniffer) Run() {
	go s.pipeline()
}

// Close destroys the Sniffer struct
func (s *Sniffer) Close() {
	s.stop <- struct{}{}
	s.tpkt.Close()
}

// New creates a new Sniffer struct
func New(timeout time.Duration) (*Sniffer, error) {
	tpkt, err := afpacket.NewTPacket(
		afpacket.OptPollTimeout(timeout))

	if err != nil {
		return nil, err
	}

	return &Sniffer{
		tpkt:    tpkt,
		stop:    make(chan struct{}),
		Packets: make(chan *Packet, 1024),
	}, nil
}
