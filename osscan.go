package gofinger

import (
	"flag"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gofinger/nmap"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	//the interface use for capture dhcp packet
	scanInterfaceFlag = flag.String("si", "enth0", "interface for scanner trigger by dhcp")
	scanFileFlag = flag.String("f", "","the path of a file filled with a list of ip  ready to be scanned")
	//scan every Mac only one time
	scannedMac = make(map[string]bool)
	scanMutex  sync.Mutex
)


type Device struct {
	Mac          string
	Vendor       string
	IP           string
	OsType       string
	DeviceType   string
	OpenPorts    string
	ScanTime     string
	ScanDuration string
}

//trigger osscan by dhcp request
func OsScanFromDhcp() {
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
				getDhcp(packet)
				wait.Done()
			}(packet)
		}
	}
	wait.Wait()
}

//filtering duplicated scan before a scan is processed
func getDhcp(packet gopacket.Packet) {
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer != nil {
		dhcPv4 := dhcpLayer.(*layers.DHCPv4)
		ip := dhcPv4.ClientIP.String()
		mac := dhcPv4.ClientHWAddr.String()
		scanMutex.Lock()
		scanned := scannedMac[mac]
		scanMutex.Unlock()

		if scanned == false && ip != "0.0.0.0" {
			//isAccess :=
			scanMutex.Lock()
			scannedMac[mac] = true
			scanMutex.Unlock()

			scanSuccess := OsScan(ip, mac,ShallowScan)
			if !scanSuccess{
				scanSuccess = OsScan(ip,mac,DeepScan)
				if !scanSuccess {
					scanMutex.Lock()
					scannedMac[mac] = false
					scanMutex.Unlock()
				}
			}
		}
	}
}

// limit the num of nmap goroutine to 5
var scanTokens = make(chan struct{}, 5)
type ScanDegree int
const (
	ShallowScan ScanDegree = 0
	DeepScan    ScanDegree = 1
)
func OsScan(ip, mac string, scanDegree ScanDegree) bool {
	scanTokens <- struct{}{}
	defer func(){<-scanTokens}()

	startTime := time.Now()
	n := nmap.New()
	//args: "-sV", "-n", "-O",  "--open"
	args := []string{"-A"}
	n.SetArgs(args...)
	if scanDegree == DeepScan {
		n.SetPorts("0-65535")
	}
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
		highAccuracyOsName string
		osAccuracy         int
		osType             []string
		osNameS            []string
		deviceTypes        []string
	)
	var device = Device{Mac: mac, IP: ip}

	for _, host := range nmapData.Hosts {
		if host.Status.State == "up" {
			for _, osMatch := range host.Os.OsMatches {
				osNameS = append(osNameS, osMatch.Name)
				tempOsAccuracy, _ := strconv.Atoi(osMatch.Accuracy)
				if tempOsAccuracy > osAccuracy {
					highAccuracyOsName = osMatch.Name
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

			if len(host.Addresses) > 1 {
				vendor := host.Addresses[1].Vendor
				device.Vendor = vendor
				if host.Addresses[1].AddrType == "mac" && host.Addresses[1].Addr != ""{
					device.Mac = host.Addresses[1].Addr
				}
			}
			if device.Mac == "" {
				device.Mac = ip
			}
			for _, port := range host.Ports {
				portStr := strconv.Itoa(port.PortId)
				//serviceStr := port.Service.Name
				//deviceTypeStr := port.Service.DeviceType
				//fmt.Println(portStr, serviceStr, deviceTypeStr)
				device.OpenPorts = device.OpenPorts + portStr + " "
			}
		}
	}

	device.OsType = formatStringArray(osNameS)
	device.DeviceType = formatStringArray(deviceTypes)
	device.ScanTime = time.Now().Format(time.ANSIC)

	switch scanDegree{
	case ShallowScan:
		if device.OsType == "" && device.DeviceType == "" {
			log.Printf("nmap shallow scan for IP %s fail,ready for deep scan\n ", device.IP)
			return false
		}
	case DeepScan:
		if device.Vendor == "" && device.OpenPorts == "" && device.OsType == "" && device.DeviceType == "" {
			log.Printf("nmap deep scan for IP %s fail\n ", device.IP)
			return false
		}
	default:
	}

	fmt.Printf("OsGuest of IP %s is %s\n", device.IP, highAccuracyOsName)
	device.ScanDuration = time.Since(startTime).String()
	StoreOsScanData(device)
	return true
}

func formatStringArray(inputStrs []string) (outputStr string) {
	for count, str := range inputStrs {
		outputStr += "[" + str + "]"
		if count >= 3 {
			break
		}
	}
	return outputStr
}

func OsScanFromFile(path string) (err error){
	fd, err := os.Open(path)
	if err != nil {
		log.Printf("Read from file %v fail", path)
		return
	}
	bytes, err := ioutil.ReadAll(fd)
	if err != nil{
		log.Printf("Read from file %v fail", path)
		return
	}
	ipArray := strings.Split(string(bytes),"\n")
	var wait sync.WaitGroup
	for _, ip := range ipArray {
		wait.Add(1)
		go func(ip string) {
			scanSuccess := OsScan(ip, "", ShallowScan)
			if !scanSuccess {
				scanSuccess = OsScan(ip, "", DeepScan)
				if !scanSuccess {
					log.Printf("nmap Scan for ip %s fail", ip)
				}
			}
			wait.Done()
		}(ip)
	}
	wait.Wait()
	return nil
}

func OsScanTrigger(){
	flag.Parse()
	if *scanFileFlag == ""{
		OsScanFromDhcp()
	}else {
		_ = OsScanFromFile(*scanFileFlag)
	}
}