package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/scs-solution/go.pkt2/capture/pcap"
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
			ip, _ := ipLayer.(*layers.IPv4)

			mutex.Lock()
			if ip.SrcIP.Equal(myIp) {
				outboundMap[ip.DstIP.String()]++
			} else if ip.DstIP.Equal(myIp) {
				inboundMap[ip.SrcIP.String()]++
			}
			mutex.Unlock()
		}
	}
}

func main() {
	go runCapture()
	go runServer()

	// https://stackoverflow.com/questions/36419054/go-projects-main-goroutine-sleep-forever
	select {}
}
