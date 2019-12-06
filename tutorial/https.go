package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type HttpsFp struct{
	Ip string
	Mac string
	Host string
	UserAgent string
	Cookie string
	Os string
}
func (hf HttpsFp) print(){
	fmt.Printf("IP: %s\nMac: %s\nUserAgent: %s\nHost:%s\nCookie: %s\nOs: %s\n",hf.Ip,hf.Mac,hf.UserAgent,hf.Host,hf.Cookie,hf.Os)
}
func main() {
	handle, err := pcap.OpenLive("ens37", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	if err := handle.SetBPFFilter("tcp and dst port 443 "); err != nil{
		panic(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil || tcpLayer.(*layers.TCP).DstPort != 443{
			continue
		}
		appLayer := packet.ApplicationLayer()
		if appLayer == nil{
			continue
		}else {
			fmt.Println("---------------------------------------------------------------------------------------------")
			httpRequest := string(appLayer.LayerContents())
			fmt.Println(httpRequest)
		}

	}
}
