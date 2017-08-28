package main

import (
	"os"

	"github.com/elastic/beats/libbeat/beat"

	"github.com/Supernomad/dnsbeat/beater"
)

func main() {
	err := beat.Run("dnsbeat", "", beater.New)
	if err != nil {
		os.Exit(1)
	}
}
