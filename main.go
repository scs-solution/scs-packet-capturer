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

		if packet.ApplicationLayer() != nil {
			body := packet.ApplicationLayer().Payload()
			if len(body) > 0 {
				bodyStr := string(body)

				fmt.Println(bodyStr)

				// modify payload of application layer
				*packet.ApplicationLayer().(*gopacket.Payload) = []byte("GET / HTTP/1.1")

				// if its tcp we need to tell it which network layer is being used
				// to be able to handle multiple protocols we can add a if clause around this
				packet.TransportLayer().(*layers.TCP).SetNetworkLayerForChecksum(packet.NetworkLayer())

				buffer := gopacket.NewSerializeBuffer()
				options := gopacket.SerializeOptions{
					ComputeChecksums: true,
					FixLengths:       true,
				}

				// Serialize Packet to get raw bytes
				if err := gopacket.SerializePacket(buffer, options, packet); err != nil {
					log.Fatalln(err)
				}

				packetBytes := buffer.Bytes()

				fmt.Println(packetBytes)

				fmt.Println("-- ")
			}
		}
	}
}
