package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/ghedo/go.pkt/capture/pcap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

var inboundMap = map[string]int{}
var outboundMap = map[string]int{}

type ResultInfo struct {
	Inbound  *map[string]int `json:"inbound"`
	Outbound *map[string]int `json:"outbound"`
}

func runServer() {
	http.HandleFunc("/hello", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("Hello World"))
	})

	http.HandleFunc("/check", func(w http.ResponseWriter, req *http.Request) {
		res := ResultInfo{
			Inbound:  &inboundMap,
			Outbound: &outboundMap,
		}
		jsonString, _ := json.Marshal(res)
		w.Write(jsonString)
	})

	http.HandleFunc("/inbound", func(w http.ResponseWriter, req *http.Request) {
		jsonString, _ := json.Marshal(inboundMap)
		w.Write(jsonString)
	})

	http.HandleFunc("/outbound", func(w http.ResponseWriter, req *http.Request) {
		jsonString, _ := json.Marshal(outboundMap)
		w.Write(jsonString)
	})

	http.ListenAndServe(":5000", nil)
}

func runCapture() {
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

	myIp := GetOutboundIP()

	var mutex = &sync.Mutex{}

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
			// log.Println("This is a IP packet!")
			ip, _ := ipLayer.(*layers.IPv4)
			// log.Printf("From src ip %s to dst ip %s\n", ip.SrcIP, ip.DstIP)

			mutex.Lock()
			if ip.SrcIP.Equal(myIp) {
				// log.Println("OutBound!")
				outboundMap[ip.DstIP.String()]++
			} else if ip.DstIP.Equal(myIp) {
				// log.Println("InBound!")
				inboundMap[ip.SrcIP.String()]++
			} else {
				// log.Println("What??")
			}
			mutex.Unlock()
		}

		continue

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

func main() {
	go runCapture()
	go runServer()

	// https://stackoverflow.com/questions/36419054/go-projects-main-goroutine-sleep-forever
	select {}
}
