package gofinger

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"strings"
)

type HttpFp struct{
	Ip 			string		`json:IP`
	Mac 		string		`json:Mac`
	Host 		string		`json:Host`
	UserAgent 	string		`json:UserAgent`
	Cookie 		string		`json:Cookie`
	Os 			string 		`json:Os`
}
func (hf HttpFp) print(){
	fmt.Printf("IP       : %s\nMac      : %s\nUserAgent: %s\nHost     :%s\nCookie   : %s\nOs       : %s\n",hf.Ip,hf.Mac,hf.UserAgent,hf.Host,hf.Cookie,hf.Os)
}


func captureHttp(packet gopacket.Packet) {
		httpFingerprint := HttpFp{}
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil || tcpLayer.(*layers.TCP).DstPort != 80{
			return
		}
		appLayer := packet.ApplicationLayer()
		if appLayer == nil{
			return
		}else{
			fmt.Println("---------------------------------------------------------------")
			httpRequest := string(appLayer.LayerContents())
			httpDatas := strings.Split(httpRequest,"\n")
			for _, httpdata := range httpDatas{
				if strings.Contains(httpdata,"User-Agent"){
					httpFingerprint.UserAgent = strings.Trim(httpdata,"User-Agent: ")
				}
				if strings.Contains(httpdata,"Cookie"){
					httpFingerprint.Cookie = strings.Trim(httpdata,"Cookie: ")
				}
				if strings.Contains(httpdata,"Host"){
					httpFingerprint.Host = strings.Trim(httpdata,"Host: ")
				}

			}

		}

		etherLayer := packet.Layer(layers.LayerTypeEthernet)
		if etherLayer != nil{
			ether := etherLayer.(*layers.Ethernet)
			httpFingerprint.Mac = ether.SrcMAC.String()
		}

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil{
			httpFingerprint.Ip = ipLayer.(*layers.IPv4).SrcIP.String()

		}

		httpFingerprint.print()
}



