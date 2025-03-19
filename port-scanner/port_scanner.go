package port_scanner

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
	"github.com/sirupsen/logrus"
	"go-vulcano/models"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PortScanner scans a range of ports using a moderate timeout per port.
// It uses a dynamic worker pool with rate limiting to avoid flooding the target.
type PortScanner struct {
	StartPort   int              // Starting port number.
	EndPort     int              // Ending port number.
	Timeout     time.Duration    // Timeout per port.
	MinWorkers  int              // Minimum number of workers.
	MaxWorkers  int              // Maximum number of workers.
	IdleTimeout time.Duration    // Idle time before a worker exits.
	RateLimit   time.Duration    // Minimum delay between connection attempts.
	Interface   NetworkInterface // Network interface to use for SYN scanning (actual pcap device name on Windows).
}

// Name returns the scanner name.
func (ps *PortScanner) Name() string {
	return "Port Scanner"
}

// Configure sets up the scanner parameters.
func (ps *PortScanner) Configure(cfg Config) {
	ps.StartPort = cfg.StartPort
	ps.EndPort = cfg.EndPort
	ps.Timeout = time.Millisecond * time.Duration(cfg.Timeout)
	ps.MinWorkers = cfg.MinWorkers
	ps.MaxWorkers = cfg.MaxWorkers
	ps.IdleTimeout = time.Millisecond * time.Duration(cfg.IdleTimeout)
	ps.RateLimit = time.Millisecond * 10
	// Optionally, set ps.NetworkInterface from cfg if available.
}

// PrepareSyn prepares the SYN scanner by setting the gateway MAC address and the network interface.
func (ps *PortScanner) PrepareSyn() error {
	err := ps.setInterface()
	if err != nil {
		return err
	}

	err = ps.setGatewayMAC()
	if err != nil {
		return err
	}

	return nil
}

// setInterface finds a suitable network interface for SYN scanning.
func (ps *PortScanner) setInterface() error {
	// Find interface to be used for packets.
	devices, err := pcap.FindAllDevs()
	if err != nil {
		logrus.Fatalf("Error finding devices: %v", err)
	}
	for _, device := range devices {
		for _, addr := range device.Addresses { // TODO: Change Wi-Fi to a general check for Windows.
			if ip := addr.IP; ip != nil && ip.To4() != nil && !ip.IsLoopback() && strings.Contains(device.Description, "Wi-Fi") {
				ps.Interface = NetworkInterface{Name: device.Name, Address: addr}
				break
			}
		}
		if ps.Interface.Name != "" {
			break
		}
	}
	if ps.Interface.Name == "" {
		return errors.New("no suitable network interface found")
	}

	return nil
}

// setGatewayMAC finds the MAC address of the gateway.
func (ps *PortScanner) setGatewayMAC() error {
	gatewayIP, err := gateway.DiscoverGateway()
	if err != nil {
		return err
	}

	handle, err := pcap.OpenLive(ps.Interface.Name, 65536, false, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	iface, err := net.InterfaceByName("Wi-Fi")
	if err != nil {
		return err
	}

	ethLayer := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(ps.Interface.Address.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(gatewayIP.To4()),
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err = gopacket.SerializeLayers(buffer, opts, ethLayer, arpLayer); err != nil {
		return err
	}

	if err = handle.WritePacketData(buffer.Bytes()); err != nil {
		return err
	}

	packetSOurce := gopacket.NewPacketSource(handle, handle.LinkType())
	timeout := time.After(5 * time.Second)
	for {
		select {
		case packet := <-packetSOurce.Packets():
			if arpLayerReply := packet.Layer(layers.LayerTypeARP); arpLayerReply != nil {
				arp, _ := arpLayerReply.(*layers.ARP)
				if net.IP(arp.SourceProtAddress).Equal(gatewayIP) {
					ps.Interface.MAC = arp.SourceHwAddress
					return nil
				}
			}
		case <-timeout:
			return nil
		}
	}
}

// Run performs the port scan for the given target.
func (ps *PortScanner) Run(target *models.TargetInfo, opts *models.Options) (*models.DTO, error) {
	// Prepare the results channel.
	resultsChan := make(chan int, ps.EndPort-ps.StartPort+1)

	// Start the scanning process.
	ps.scan(target.Domain, opts.ScanMode, resultsChan)

	// Collect and sort open ports.
	var openPorts []int
	for port := range resultsChan {
		openPorts = append(openPorts, port)
	}
	sort.Ints(openPorts)
	logrus.Infof("Open ports on %s: %v", target.Domain, openPorts)

	// Cache the results.
	var result models.DTO
	result.Ports = openPorts

	return &result, nil
}

// scan starts the scanning procedure.
func (ps *PortScanner) scan(target string, mode string, resultsChan chan int) {
	// Set a global timeout based on the number of ports plus an extra buffer.
	totalTimeout := time.Duration(ps.EndPort-ps.StartPort)*ps.Timeout + 5*time.Second
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()

	// Create a channel for port numbers.
	portChan := make(chan int, 100)

	var wg sync.WaitGroup
	var currentWorkers = int32(ps.MinWorkers)

	limiter := time.NewTicker(ps.RateLimit)
	defer limiter.Stop()

	// Use a faster rate limiter for SYN scanning.
	if mode == "syn" {
		limiter = time.NewTicker(time.Nanosecond * 1)
	}

	// Spawn the initial pool of workers.
	for i := 0; i < ps.MinWorkers; i++ {
		wg.Add(1)
		if mode == "tcp" {
			go ps.tcpWorker(target, &currentWorkers, portChan, resultsChan, ctx, limiter, &wg)
		} else {
			go ps.synWorker(target, &currentWorkers, portChan, resultsChan, ctx, limiter, &wg)
		}
	}

	// Producer: enqueue all port numbers.
	go func() {
		for port := ps.StartPort; port <= ps.EndPort; port++ {
			select {
			case <-ctx.Done():
				return
			default:
				portChan <- port
				// Dynamically spawn more workers if pending tasks exceed a threshold.
				if len(portChan) > 10 && atomic.LoadInt32(&currentWorkers) < int32(ps.MaxWorkers) {
					atomic.AddInt32(&currentWorkers, 1)
					wg.Add(1)
					if mode == "tcp" {
						go ps.tcpWorker(target, &currentWorkers, portChan, resultsChan, ctx, limiter, &wg)
					} else {
						go ps.synWorker(target, &currentWorkers, portChan, resultsChan, ctx, limiter, &wg)
					}
				}
			}
		}
		close(portChan)
	}()

	wg.Wait()
	close(resultsChan)
}

// worker is a generic worker function that scans ports using a specified function.
func (ps *PortScanner) worker(target string, currentWorkers *int32, portChan chan int, resultsChan chan int, ctx context.Context, limiter *time.Ticker, wg *sync.WaitGroup, scanFunc func(target string, port int, ctx context.Context, resultsChan chan int)) {
	defer wg.Done()

	idleTimer := time.NewTimer(ps.IdleTimeout)
	defer idleTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			atomic.AddInt32(currentWorkers, -1)
			return
		case port, ok := <-portChan:
			if !ok {
				atomic.AddInt32(currentWorkers, -1)
				return
			}
			// Wait for a token from the rate limiter.
			<-limiter.C

			if !idleTimer.Stop() {
				<-idleTimer.C
			}
			idleTimer.Reset(ps.IdleTimeout)

			// Call the scan function.
			scanFunc(target, port, ctx, resultsChan)

		case <-idleTimer.C:
			atomic.AddInt32(currentWorkers, -1)
			return
		}
	}
}

// tcpWorker scans a target port using a TCP connection.
func (ps *PortScanner) tcpWorker(target string, currentWorkers *int32, portChan chan int, resultsChan chan int, ctx context.Context, limiter *time.Ticker, wg *sync.WaitGroup) {
	ps.worker(target, currentWorkers, portChan, resultsChan, ctx, limiter, wg, ps.dialTcp)
}

// dialTcp dials the target port and sends the result to the results channel.
func (ps *PortScanner) dialTcp(target string, port int, ctx context.Context, resultsChan chan int) {
	address := fmt.Sprintf("%s:%d", target, port)
	// Create a per-dial context with the specified timeout.
	dialCtx, cancelDial := context.WithTimeout(ctx, ps.Timeout)
	defer cancelDial()

	// Dial the target port.
	startTime := time.Now()

	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", address)

	// Simple throttle if dial took too long.
	duration := time.Since(startTime)
	if duration > ps.Timeout {
		time.Sleep(100 * time.Millisecond)
	}

	// Check if the port is open.
	if err == nil {
		resultsChan <- port
		conn.Close()
		logrus.Debugf("Port %d open (in %v)", port, duration)
	} else {
		logrus.Tracef("Port %d closed (error: %v, in %v)", port, err, duration)
	}
}

// synWorker scans a target port using a SYN packet.
func (ps *PortScanner) synWorker(target string, currentWorkers *int32, portChan chan int, resultsChan chan int, ctx context.Context, limiter *time.Ticker, wg *sync.WaitGroup) {
	ps.worker(target, currentWorkers, portChan, resultsChan, ctx, limiter, wg, ps.sendSyn)
}

// sendSyn sends a SYN packet to the target port and waits for a response.
func (ps *PortScanner) sendSyn(target string, port int, ctx context.Context, resultsChan chan int) {
	// Resolve target IP
	ips, err := net.DefaultResolver.LookupHost(ctx, target)
	if err != nil || len(ips) == 0 {
		logrus.Errorf("Failed to resolve host %s: %v", target, err)
		return
	}
	dstIP := net.ParseIP(ips[0])

	// Choose random source port
	srcPort := uint16(40000 + rand.Intn(25000))

	// Open the interface for packet capture
	handle, err := pcap.OpenLive(ps.Interface.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		logrus.Errorf("Failed to open interface %s: %v", ps.Interface, err)
		return
	}
	defer handle.Close()

	// Set BPF filter
	filter := fmt.Sprintf("tcp and src host %s and tcp dst port %d", dstIP.String(), srcPort)
	if err = handle.SetBPFFilter(filter); err != nil {
		logrus.Warnf("Failed to set BPF filter: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	// Build SYN packet
	rawPacket, err := ps.buildSYNPacket(ps.Interface.Address.IP, dstIP, srcPort, port)
	if err != nil {
		logrus.Errorf("Failed to build SYN packet: %v", err)
		return
	}

	// Send SYN packet
	if err = handle.WritePacketData(rawPacket); err != nil {
		logrus.Errorf("Failed to send packet: %v", err)
		return
	}

	ps.waitForResponse(packets, srcPort, uint16(port), ps.Timeout, resultsChan)
}

// buildSYNPacket constructs and serializes a SYN packet with the given IPs and ports.
func (ps *PortScanner) buildSYNPacket(srcIP, dstIP net.IP, srcPort uint16, dstPort int) ([]byte, error) {
	iface, err := net.InterfaceByName("Wi-Fi")
	if err != nil {
		return nil, err
	}

	ethLayer := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr(ps.Interface.MAC),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     rand.Uint32(),
		SYN:     true,
		Window:  14600,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buffer, opts, ethLayer, ipLayer, tcpLayer); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// waitForResponse waits for a response packet SYN-ACK on the given port.
func (ps *PortScanner) waitForResponse(packets chan gopacket.Packet, srcPort, dstPort uint16, timeout time.Duration, resultsChan chan int) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case packet := <-packets:
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if tcp.DstPort == layers.TCPPort(srcPort) && tcp.SrcPort == layers.TCPPort(dstPort) {
					if tcp.SYN && tcp.ACK {
						logrus.Println("Port open:", dstPort)
						resultsChan <- int(dstPort)
					}
				}
			}
		case <-timer.C:
			return false
		}
	}
}
