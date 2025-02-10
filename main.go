package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/schollz/progressbar/v3"
)

// PacketCapturer handles network packet capturing operations
type PacketCapturer struct {
	handle *pcap.Handle
	stop   bool
}

var packetCount uint64

// New creates a new PacketCapturer instance
// iface: network interface name
// filter: BPF filter expression
// Returns initialized PacketCapturer or error if initialization fails
func New(iface, filter string) (*PacketCapturer, error) {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("pcap.OpenLive error: %w", err)
	}

	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("BPF filter error: %w", err)
	}

	return &PacketCapturer{
		handle: handle,
		stop:   false,
	}, nil
}

func (pc *PacketCapturer) Start() {
	packetSource := gopacket.NewPacketSource(pc.handle, pc.handle.LinkType())
	for packet := range packetSource.Packets() {
		if pc.stop {
			break
		}
		pc.processPacket(packet)
	}
}

func (pc *PacketCapturer) Stop() {
	pc.stop = true
	if pc.handle != nil {
		pc.handle.Close()
	}
}

// processPacket handles individual packet processing
func (pc *PacketCapturer) processPacket(packet gopacket.Packet) {
	atomic.AddUint64(&packetCount, 1)

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}

	dnsPacket, _ := dnsLayer.(*layers.DNS)
	ProcessDNSPacket(dnsPacket, time.Now())
}

// ProcessDNSPacket analyzes and displays DNS packet contents
// dnsPacket: parsed DNS packet structure
// ts: timestamp of packet capture
func ProcessDNSPacket(dnsPacket *layers.DNS, ts time.Time) {
	log.Println("------ DNS Packet ------")
	fmt.Printf("Processed at: %s\n", ts.Format(time.RFC3339))
	fmt.Printf("Request ID: %d\n", dnsPacket.ID)
	fmt.Printf("QR Flag (Query/Response): %v\n", dnsPacket.QR)

	// Display DNS questions section
	if len(dnsPacket.Questions) > 0 {
		for _, question := range dnsPacket.Questions {
			fmt.Printf("Question: %s, Type: %v\n", string(question.Name), question.Type)
		}
	}

	// Display DNS answers section (if response packet)
	if dnsPacket.QR && len(dnsPacket.Answers) > 0 {
		for _, answer := range dnsPacket.Answers {
			fmt.Printf("Answer: %s -> ", string(answer.Name))
			if answer.IP != nil {
				fmt.Printf("%s\n", answer.IP)
			} else {
				fmt.Printf("Unknown answer type\n")
			}
		}
	}
	fmt.Println("------------------------")
}

// findInterface automatically detects suitable network interface
// Returns interface name or error if no valid interface found
func findInterface() (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("pcap.FindAllDevs error: %w", err)
	}

	netInts, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("net.Interfaces error: %w", err)
	}

	for _, dev := range devices {
		if len(dev.Addresses) == 0 {
			continue
		}

		// Find matching network interface
		var netInt *net.Interface
		for i, ni := range netInts {
			if ni.Name == dev.Name {
				netInt = &netInts[i]
				break
			}
		}
		if netInt == nil {
			continue
		}

		if netInt.Flags&net.FlagLoopback != 0 {
			continue
		}
		if netInt.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := netInt.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
				return dev.Name, nil
			}
		}
	}

	return "", fmt.Errorf("no suitable network interface found")
}

func main() {
	iface := os.Getenv("DNS_SNIFFER_INTERFACE")
	var err error

	if iface == "" {
		iface, err = findInterface()
		if err != nil {
			log.Fatalf("Interface detection failed: %v", err)
		}
	}

	filter := "udp and port 53"
	log.Println("Starting DNS Sniffer on interface:", iface)

	capturer, err := New(iface, filter)
	if err != nil {
		log.Fatalf("Capture initialization failed on %s: %v", iface, err)
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)

	bar := progressbar.NewOptions(
		-1,
		progressbar.OptionSetDescription("🐇 Capturing DNS packets..."),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionSetWidth(30),
		progressbar.OptionShowCount(),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	go func() {
		for {
			select {
			case <-stopChan:
				return
			default:
				count := atomic.LoadUint64(&packetCount)
				bar.Set(int(count))
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	go capturer.Start()

	<-stopChan
	log.Println("Termination signal received. Stopping capture...")
	capturer.Stop()
	bar.Finish()
	time.Sleep(1 * time.Second)
}
