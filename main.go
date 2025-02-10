package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/schollz/progressbar/v3"
)

// PacketCapturer handles network packet capturing and processing
type PacketCapturer struct {
	handle     *pcap.Handle         // pcap handle for packet capture
	stop       bool                 // control flag for stopping capture
	workers    int                  // number of parallel workers
	packetChan chan gopacket.Packet // channel for passing packets to workers
	wg         sync.WaitGroup       // wait group for worker management
}

var packetCount uint64

var (
	defaultWorkers   = runtime.NumCPU() 
	packetBufferSize = 1000           
)

// New creates a new PacketCapturer instance
func New(iface, filter string) (*PacketCapturer, error) {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("pcap.OpenLive error: %w", err)
	}

	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("BPF filter error: %w", err)
	}

	workers := getWorkerCount()

	return &PacketCapturer{
		handle:     handle,
		stop:       false,
		workers:    workers,
		packetChan: make(chan gopacket.Packet, packetBufferSize),
	}, nil
}

func getWorkerCount() int {
	if workers := os.Getenv("DNS_SNIFFER_WORKERS"); workers != "" {
		if n, err := strconv.Atoi(workers); err == nil && n > 0 {
			return n
		}
	}
	return defaultWorkers
}

func (pc *PacketCapturer) Start() {
	for i := 0; i < pc.workers; i++ {
		pc.wg.Add(1)
		go pc.worker()
	}

	packetSource := gopacket.NewPacketSource(pc.handle, pc.handle.LinkType())

	for packet := range packetSource.Packets() {
		if pc.stop {
			break
		}
		pc.packetChan <- packet
	}

	close(pc.packetChan)
	pc.wg.Wait()
}

func (pc *PacketCapturer) worker() {
	defer pc.wg.Done()
	for packet := range pc.packetChan {
		pc.processPacket(packet)
	}
}


func (pc *PacketCapturer) Stop() {
	pc.stop = true
	if pc.handle != nil {
		pc.handle.Close()
	}
}

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

	if len(dnsPacket.Questions) > 0 {
		for _, question := range dnsPacket.Questions {
			fmt.Printf("Question: %s, Type: %v\n", string(question.Name), question.Type)
		}
	}

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

		var netInt *net.Interface
		for i, ni := range netInts {
			if ni.Name == dev.Name {
				netInt = &netInts[i]
				break
			}
		}

		if netInt == nil ||
			netInt.Flags&net.FlagLoopback != 0 ||
			netInt.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := netInt.Addrs()
		if err != nil {
			log.Printf("Interface %s: address error - %v", netInt.Name, err)
			continue
		}

		// Check for valid IPv4 address
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
	log.Printf("Starting DNS Sniffer on interface %s (%d workers)", iface, getWorkerCount())
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

	// Start progress bar updater
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
