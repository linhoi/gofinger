package gofinger

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mssola/user_agent"
	"strings"
)

type HttpFp struct {
	Ip        string `json:IP`
	Mac       string `json:Mac`
	Host      string `json:Host`
	UserAgent string `json:UserAgent`
	Cookie    string `json:Cookie`
	OS        string `json:Os`
}

func (hf HttpFp) print() {
	fmt.Printf("HTTPingerPrint\nIP       : %s\nMac      : %s\nUserAgent: %s\nHost     : %s\nCookie   : %s\nOS       : %s\n", hf.Ip, hf.Mac, hf.UserAgent, hf.Host, hf.Cookie, hf.OS)
}

func captureHttp(packet gopacket.Packet) {
	httpFingerprint := HttpFp{}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil || tcpLayer.(*layers.TCP).DstPort != 80 {
		return
	}
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return
	} else {
		httpRequest := string(appLayer.LayerContents())
		if !strings.Contains(httpRequest,"User-Agent:"){
			return
		}
		httpDatas := strings.Split(httpRequest, "\n")
		for _, httpdata := range httpDatas {
			if strings.Contains(httpdata, "User-Agent") {
				httpFingerprint.UserAgent = strings.Trim(httpdata, "User-Agent: ")
				httpFingerprint.OS = user_agent.New(httpFingerprint.UserAgent).OS()
			}
			if strings.Contains(httpdata, "Cookie") {
				httpFingerprint.Cookie = strings.Trim(httpdata, "Cookie: ")
			}
			if strings.Contains(httpdata, "Host") {
				httpFingerprint.Host = strings.Trim(httpdata, "Host: ")
			}

		}

	}

	etherLayer := packet.Layer(layers.LayerTypeEthernet)
	if etherLayer != nil {
		ether := etherLayer.(*layers.Ethernet)
		httpFingerprint.Mac = ether.SrcMAC.String()
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		httpFingerprint.Ip = ipLayer.(*layers.IPv4).SrcIP.String()

	}
	fmt.Println("---------------------------------------------------------------")
	httpFingerprint.print()
}
