package main


import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"log"
	"os"
	"strings"
	"time"
)

func getDiviceInfo(){
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Devices found")
	for _, device := range devices{
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}

	}
}

var (
	device			string = "ens33"
	snapshot		int32  = 1024
	promiscuous		bool   = false
	err  			error
	timeout			time.Duration = 30 * time.Second
	handle			*pcap.Handle
	packetCount		int = 0
)

func liveCapture(){
	handle ,err := pcap.OpenLive(device,snapshot,promiscuous,timeout)
	if err != nil {log.Fatal(err)}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle,handle.LinkType())
	for packet := range packetSource.Packets(){
		fmt.Println(packet)
	}
}

func writePcapFile(){
	f, _ := os.Create("test.pcap")
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(uint32(snapshot),layers.LinkTypeEthernet)
	defer f.Close()

	timeout  = -1 * time.Second
	handle, err = pcap.OpenLive(device, snapshot,promiscuous, timeout)
	if err != nil {
		fmt.Printf("Error opening device %s: %w", device,err)
		os.Exit(1)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		packetCount++

		if packetCount > 100 {
			break
		}
	}

}

func openPcapFile(){
	handle, err = pcap.OpenOffline("test.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer  handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
}

func setFilters(){
	handle, err := pcap.OpenLive(device, snapshot,promiscuous, timeout)
	if err != nil {log.Fatal(err)}
	defer handle.Close()

	var filter = "tcp and port 80"
	err = handle.SetBPFFilter(filter)
	if err != nil {log.Fatal(err)}
	fmt.Println("Only capturing TCP port on 80 port")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets(){
		fmt.Println(packet)
	}

}


func printPacketInfo( packet gopacket.Packet){
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		fmt.Println("Ethernet layer detected")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
		fmt.Println("Destination MAC:", ethernetPacket.DstMAC)
		fmt.Println("Ethernet type:", ethernetPacket.EthernetType)
		fmt.Println()

	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println()
	}

	// Let's see if the packet is TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)

		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		fmt.Println("Sequence number: ", tcp.Seq)
		fmt.Println()
	}

	// Iterate over all layers, printing out each layer type
	fmt.Println("All packet layers:")
	for _, layer := range packet.Layers() {
		fmt.Println("- ", layer.LayerType())
	}

	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		fmt.Println("Application layer/Payload found.")
		fmt.Println(string(applicationLayer.Payload()))

		// Search for a string inside the payload
		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
			fmt.Println("HTTP found!")
		}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}

func decodePacketLayers(){
	handle, err = pcap.OpenLive(device, snapshot, promiscuous, timeout)
	if err != nil {log.Fatal(err) }
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		printPacketInfo(packet)
	}
}


func main0(){
	//openPcapFile()
	//setFilters()
	decodePacketLayers()
}