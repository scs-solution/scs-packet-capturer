package main

import (
	"fmt"
	"log"

	"github.com/ghedo/go.pkt/capture/pcap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	src, err := pcap.Open("eth0")
	if err != nil {
		log.Fatal(err)
	}
	defer src.Close()

	// you may configure the source further, e.g. by activating
	// promiscuous mode.

	err = src.Activate()
	if err != nil {
		log.Fatal(err)
	}

	for {
		buf, err := src.Capture()
		if err != nil {
			log.Fatal(err)
		}

		log.Println("PACKET!!!")

		// do something with the packet
		packet := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.Default)

		// Get the TCP layer from this packet
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			fmt.Println("This is a TCP packet!")
			// Get actual TCP data from this layer
			tcp, _ := tcpLayer.(*layers.TCP)
			fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
		}

		// Iterate over all layers, printing out each layer type
		for _, layer := range packet.Layers() {
			fmt.Println("PACKET LAYER:", layer.LayerType())

			body := string(layer.LayerPayload())

			fmt.Println(body)
		}
	}
}
