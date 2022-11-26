package main

import (
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

		packet := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer == nil {
			continue
		}

		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			log.Println("This is a IP packet!")
			ip, _ := ipLayer.(*layers.IPv4)
			log.Printf("From src ip %s to src ip %s\n", ip.SrcIP, ip.DstIP)
		}

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			log.Println("This is a TCP packet!")
			tcp, _ := tcpLayer.(*layers.TCP)
			log.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
		}

		for _, layer := range packet.Layers() {
			log.Println("PACKET LAYER:", layer.LayerType())
			// body := string(layer.LayerPayload())
			// log.Println(body)
			log.Println(gopacket.LayerDump(layer))
		}

		// if packet.ApplicationLayer() != nil {
		// 	body := packet.ApplicationLayer().Payload()
		// 	if len(body) > 0 {
		// 		buffer := gopacket.NewSerializeBuffer()
		// 		options := gopacket.SerializeOptions{
		// 			ComputeChecksums: true,
		// 			FixLengths:       true,
		// 		}

		// 		if err := gopacket.SerializePacket(buffer, options, packet); err != nil {
		// 			log.Fatalln(err)
		// 		}

		// 		packetBytes := buffer.Bytes()

		// 		fmt.Println(packetBytes)

		// 		fmt.Println("-- ")
		// 	}
		// }
	}
}
