package beater

import (
	"fmt"
	"time"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/publisher"

	"github.com/Supernomad/dnsbeat/config"
	"github.com/Supernomad/dnsbeat/sniffer"
)

// Dnsbeat is a new awesome beat
type Dnsbeat struct {
	done    chan struct{}
	config  config.Config
	client  publisher.Client
	sniffer *sniffer.Sniffer
}

// Creates beater
func New(b *beat.Beat, cfg *common.Config) (beat.Beater, error) {
	config := config.DefaultConfig
	if err := cfg.Unpack(&config); err != nil {
		return nil, fmt.Errorf("Error reading config file: %v", err)
	}

	sniffer, err := sniffer.New(2 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("Error setting up sniffer: %v", err)
	}

	bt := &Dnsbeat{
		done:    make(chan struct{}),
		config:  config,
		sniffer: sniffer,
	}

	return bt, nil
}

func (bt *Dnsbeat) Run(b *beat.Beat) error {
	logp.Info("dnsbeat is running! Hit CTRL-C to stop it.")

	bt.client = b.Publisher.Connect()
	bt.sniffer.Run()
	for {
		select {
		case <-bt.done:
			return nil
		case pkt := <-bt.sniffer.Packets:
			event := common.MapStr{
				"@timestamp":  common.Time(time.Now()),
				"type":        b.Name,
				"proto":       pkt.Proto,
				"client_ip":   pkt.SrcIP,
				"client_port": pkt.SrcPort,
				"server_ip":   pkt.DstIP,
				"server_port": pkt.DstPort,
				"dns":         pkt.DNS,
			}
			bt.client.PublishEvent(event)
		}
	}
}

func (bt *Dnsbeat) Stop() {
	bt.client.Close()
	close(bt.done)
}
