package gofinger

/*****************************
抓取dhcp设备指纹的demo
抓取的信息定义在结构体dhcpFP内
****************************** */

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

//dhcp设备指纹结构体
type DhcpFP struct {
	Client       string `json:client`
	Mac          string `json:mac`
	HostName     string `json:hostName`
	Vendor       string `json:vendor`
	OptionList   []byte `json:optionList`
	Option55List []byte `json:option55List`
}

//通道
var chDhcpFp = make(chan []byte)

//格式化打印DHCP指纹
func (df *DhcpFP) print() {
	fmt.Println(" client       :", df.Client, "\n",
		"mac          :", df.Mac, "\n",
		"hosName      :", df.HostName, "\n",
		"vendor       :", df.Vendor, "\n",
		"optionList  :", df.OptionList, "\n",
		"option55List :", df.Option55List)

}
func (df *DhcpFP) Print() {
	fmt.Printf("client       :%s\nmac          :%v\nhosName      :%s\nvendor       :%s\noptionList   :%v\noption55List :%v\n",
		df.Client, df.Mac, df.HostName, df.Vendor, df.OptionList, df.Option55List)
}

//运行选项
// -i 选项指定接口，默认会监听所有以太网接口
var interfaceFlag = flag.String("i", "", "Interface to be captured")
// -f 选项指定过滤器，默认过滤出67和68端口
var filter = flag.String("f", "((udp and (port 67 or 68)) or (tcp and port 80)) and not host 0.0.0.0", "BPF filter for pcap")

var jsonDatas [][]byte

func Run() {
	//Dont forget to parse flag , otherwise if may not work
	flag.Parse()
	fmt.Println("pcap version: ", pcap.Version())
	//get every interface in the device
	var interFaces []string
	devices, _ := pcap.FindAllDevs()
	for _, device := range devices {
		if strings.Contains(device.Name, "en") {
			interFaces = append(interFaces, device.Name)
			ip := device.Addresses[0].IP
			fmt.Printf("InterFace  %s with ip address %s Found \n", device.Name, ip)
		}
	}

	//scan the interfaces to find out if the interfaceFlag exist
	if *interfaceFlag != ""{
		interFaces = strings.Split(*interfaceFlag ," ")
	}
	var deviceExist [10]bool
	for i:=0;  i < len(devices); i++{
		for j:=0; j < len(interFaces) && j < 10 ; j++ {
			if interFaces[j] == devices[i].Name {
				deviceExist[j] = true
			}
		}
	}
	for i:=0;i < len(interFaces);i++ {
		if deviceExist[i] == false  {
			fmt.Printf("Interface named %v not found, \n "+
				"you can get interface with command :ip addr\n", interFaces)
			return
		}
	}

	//attach every dhcpfingerprint to a http url
	go func() {
		var gonum = 0
		for {
			data := <-chDhcpFp
			var dataExist bool
			for _ ,jsonData := range jsonDatas{
				if bytes.Equal(jsonData,data){
					dataExist = true
					break
				}
			}
			if !dataExist {
				gonum++
				jsonDatas = append(jsonDatas, data)
				http.HandleFunc("/"+"ID="+strconv.Itoa(gonum), func(w http.ResponseWriter, r *http.Request) {
					_, err := w.Write(data)
					if err != nil {
						panic(err)
					}
				})
			}
		}
	}()
	go func() {
		log.Fatal(http.ListenAndServe(":8000", nil))
	}()

	//capture dhcp package in concurrency
	var wait sync.WaitGroup
	for _, interFace := range interFaces {
			wait.Add(1)
			go func(interFace string) {
				defer wait.Done()
				fmt.Println("Capture DHCP FingerPrint on Interface:", interFace)
				capture(interFace)
			}(interFace)
	}
	wait.Wait()

}

//capture dhcp and http package
func capture(interFace string) {
	handle, err := pcap.OpenLive(
		interFace,
		int32(65535),
		false,
		-1,
	)
	if err != nil {
		panic(err.Error())
	}
	defer handle.Close()

	err = handle.SetBPFFilter(*filter)
	if err != nil {
		fmt.Println("ERROR Happened: filter syntax error,please use the filter with right syntax")
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	for packet := range packets {
		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
		if dhcpLayer != nil {
			captureDhcp(packet)
		}else{
			captureHttp(packet)
		}
		//httpLayer := packet.Layer(http)
	}
}
func captureDhcp(packet gopacket.Packet ) bool {
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer != nil {
			dhcPv4 := dhcpLayer.(*layers.DHCPv4)
			options := dhcPv4.Options

			dhcpFingerPrinter := DhcpFP{
				Client: dhcPv4.ClientIP.String(),
				Mac:    dhcPv4.ClientHWAddr.String(),
			}

			for _, option := range options {
				dhcpFingerPrinter.OptionList = append(dhcpFingerPrinter.OptionList, byte(option.Type))
				switch option.Type {
				case layers.DHCPOptHostname:
					dhcpFingerPrinter.HostName = string(option.Data)
				case layers.DHCPOptClassID:
					dhcpFingerPrinter.Vendor = string(option.Data)
				case layers.DHCPOptParamsRequest:
					for _, v := range option.Data {
						dhcpFingerPrinter.Option55List = append(dhcpFingerPrinter.Option55List, v)
					}
				default:

				}
			}

			fmt.Println("--------------------------------------------------------------------")
			dhcpFingerPrinter.Print()
			//fmt.Println("----------------------")
			data, err := json.MarshalIndent(dhcpFingerPrinter, "", "   ")
			if err != nil {
				log.Fatalf("Json Marshaling failed: %s", err)
			}
			chDhcpFp <- data
			//fmt.Printf("Json Data:%s\n", data)

			return true
	}
	return false
}


