package gofinger

import (
	"flag"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gofinger/nmap"
	"log"
	"strconv"
	"sync"
	"time"
)

var (
	//the interface use for feach dhcp packet
	scanInterfaceFlag = flag.String("si", "enth0", "interface for scanner trigger by dhcp")
)

//scan every Mac only one time
var scannedMac = make(map[string]bool)
var scanMutex sync.Mutex

type Device struct {
	Mac        string
	Vendor     string
	IP         string
	OsType     string
	DeviceType string
	OpenPorts  string
}

//trigger osscan by dhcp request
func OsScanTrigger() {
	flag.Parse()

	handle, err := pcap.OpenLive(
		*scanInterfaceFlag,
		int32(65535),
		false,
		-1,
	)
	if err != nil {
		log.Println("[Panic]", err)
		return
	}
	defer handle.Close()

	err = handle.SetBPFFilter("udp and port 67 and not host 0.0.0.0")
	if err != nil {
		log.Println("ERROR Happened: filter syntax error")
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	//capture dhcp packet for osscan
	var wait sync.WaitGroup
	for packet := range packets {
		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
		if dhcpLayer != nil {
			wait.Add(1)
			go func(packet gopacket.Packet) {
				scanDhcp(packet)
				wait.Done()
			}(packet)
		}
	}
	wait.Wait()
}

//filtering replicated scan before a scan is processed
func scanDhcp(packet gopacket.Packet) {
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer != nil {
		dhcPv4 := dhcpLayer.(*layers.DHCPv4)
		ip := dhcPv4.ClientIP.String()
		mac := dhcPv4.ClientHWAddr.String()
		scanMutex.Lock()
		scanned := scannedMac[mac]
		scanMutex.Unlock()

		if scanned == false && ip != "0.0.0.0" {
			scanMutex.Lock()
			scannedMac[mac] = true
			scanMutex.Unlock()
			success := OsScan(ip, mac)
			if !success {
				scanMutex.Lock()
				scannedMac[mac] = false
				scanMutex.Unlock()
			}

		}
	}
}

func OsScan(ip, mac string) bool {
	startTime := time.Now()
	n := nmap.New()
	args := []string{"-A"} //""-sV", "-n", "-O",  "--open"}
	n.SetArgs(args...)
	//n.SetPorts("0-65535")
	n.SetHosts(ip)

	err := n.Run()
	if err != nil {
		log.Println("Nmap Scan Failed: ", err)
		return false
	}

	nmapData, err := n.Parse()
	if err != nil {
		log.Println("Parse Error: ", err)
		return false
	}

	var (
		osName      string
		osAccuracy  int
		osType      []string
		osNameS     []string
		deviceTypes []string
	)

	var device = Device{Mac: mac, IP: ip}

	for _, host := range nmapData.Hosts {
		if host.Status.State == "up" {
			for _, osMatch := range host.Os.OsMatches {
				osNameS = append(osNameS, osMatch.Name)
				tempOsAccuracy, _ := strconv.Atoi(osMatch.Accuracy)
				if tempOsAccuracy > osAccuracy {
					osName = osMatch.Name
					for _, osclasss := range osMatch.OsClasses {
						osType = append(osType, osclasss.Type)

					}
					osAccuracy = tempOsAccuracy
				}
				for _, osclasss := range osMatch.OsClasses {
					var existOstype = false
					for _, ostype := range deviceTypes {
						if ostype == osclasss.Type {
							existOstype = true
						}
					}
					if existOstype == false {
						deviceTypes = append(deviceTypes, osclasss.Type)
					}
				}
			}

			ipAddr := host.Addresses[0].Addr
			fmt.Println("IP: ", ipAddr)
			if len(host.Addresses) > 1 {
				vendor := host.Addresses[1].Vendor
				device.Vendor = vendor
				fmt.Println("Mac: ", mac)
				fmt.Println("Vendor: ", vendor)
			}
			fmt.Println("Os: ", osName)
			fmt.Println("OsType: ", osType)
			fmt.Println("OSGuest:", osNameS)
			fmt.Println("DeviceGuest:", deviceTypes)

			for _, port := range host.Ports {
				portStr := strconv.Itoa(port.PortId)
				serviceStr := port.Service.Name
				deviceTypeStr := port.Service.DeviceType
				fmt.Println(portStr, serviceStr, deviceTypeStr)
				device.OpenPorts = device.OpenPorts + portStr + " "
			}

		}
	}

	//store osscan data when osscan is success
	//if os type or device type is too much ,cut it to lenth = 3

	device.OsType = fmt.Sprintln(osNameS)
	device.DeviceType = fmt.Sprintln(deviceTypes)

	fmt.Println(time.Since(startTime))
	StoreOsScanData(device)
	return true

}
