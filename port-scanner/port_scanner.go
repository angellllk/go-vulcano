package port_scanner

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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
	StartPort   int           // Starting port number.
	EndPort     int           // Ending port number.
	Timeout     time.Duration // Timeout per port.
	MinWorkers  int           // Minimum number of workers.
	MaxWorkers  int           // Maximum number of workers.
	IdleTimeout time.Duration // Idle time before a worker exits.
	RateLimit   time.Duration // Minimum delay between connection attempts.
	Interface   string        // Network interface to use for SYN scanning (actual pcap device name on Windows).
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
	// Optionally, set ps.Interface from cfg if available.
}

// tcpWorker scans ports using a TCP connect method.
func (ps *PortScanner) tcpWorker(target string, currentWorkers *int32, portChan chan int, resultsChan chan int, ctx context.Context, limiter *time.Ticker, wg *sync.WaitGroup) {
	defer wg.Done()

	// Set a timeout for the dialer.
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
			// Reset idle timer.
			if !idleTimer.Stop() {
				<-idleTimer.C
			}
			idleTimer.Reset(ps.IdleTimeout)

			// Dial the target port.
			ps.dialTcp(target, port, ctx, resultsChan)

		case <-idleTimer.C:
			// Worker idle: exit.
			atomic.AddInt32(currentWorkers, -1)
			return
		}
	}
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

// synWorker scans ports using SYN scanning.
func (ps *PortScanner) synWorker(target string, currentWorkers *int32, portChan chan int, resultsChan chan int, ctx context.Context, limiter *time.Ticker, wg *sync.WaitGroup) {
	defer wg.Done()

	idleTimer := time.NewTimer(ps.IdleTimeout)
	defer idleTimer.Stop()

	// Get the first available network interface
	iface, srcIP, err := getFirstInterface()
	if err != nil {
		logrus.Errorf("Failed to find network interface: %v", err)
		atomic.AddInt32(currentWorkers, -1)
		return
	}

	// Open the interface for packet capture
	handle, err := pcap.OpenLive(iface.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		logrus.Errorf("Failed to open interface %s: %v", iface.Name, err)
		atomic.AddInt32(currentWorkers, -1)
		return
	}
	defer handle.Close()

	// Resolve target IP
	ips, err := net.DefaultResolver.LookupHost(ctx, target)
	if err != nil || len(ips) == 0 {
		logrus.Errorf("Failed to resolve host %s: %v", target, err)
		atomic.AddInt32(currentWorkers, -1)
		return
	}
	dstIP := net.ParseIP(ips[0])

	// Choose random source port
	srcPort := uint16(40000 + rand.Intn(25000))

	// Set BPF filter
	filter := fmt.Sprintf("tcp and src host %s and tcp dst port %d", dstIP.String(), srcPort)
	if err = handle.SetBPFFilter(filter); err != nil {
		logrus.Warnf("Failed to set BPF filter: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

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
			<-limiter.C

			if !idleTimer.Stop() {
				<-idleTimer.C
			}
			idleTimer.Reset(ps.IdleTimeout)

			// Send SYN packet
			rawPacket, err := buildSYNPacket(srcIP, dstIP, srcPort, port)
			if err != nil {
				logrus.Errorf("Failed to build SYN packet: %v", err)
				continue
			}

			if err = handle.WritePacketData(rawPacket); err != nil {
				logrus.Errorf("Failed to send packet: %v", err)
				continue
			}

			// Wait for response
			if open := waitForResponse(packets, srcPort, uint16(port), dstIP, ps.Timeout); open {
				resultsChan <- port
				logrus.Debugf("Port %d is open", port)
			}

		case <-idleTimer.C:
			atomic.AddInt32(currentWorkers, -1)
			return
		}
	}
}

// getFirstInterface returns the first non-loopback interface and its IPv4 address
func getFirstInterface() (*net.Interface, net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ip := ipnet.IP.To4(); ip != nil {
					return &iface, ip, nil
				}
			}
		}
	}

	return nil, nil, fmt.Errorf("no suitable interface found")
}

// buildSYNPacket constructs and serializes a SYN packet with the given IPs and ports.
func buildSYNPacket(srcIP, dstIP net.IP, srcPort uint16, dstPort int) ([]byte, error) {
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
	if err := gopacket.SerializeLayers(buffer, opts, ipLayer, tcpLayer); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// awaitSYNResponse waits for a response packet for the SYN packet sent.
// Returns true if a SYN/ACK is received (port open), false if RST or timeout.
func awaitSYNResponse(packetChan <-chan gopacket.Packet, srcPort uint16, dstPort int, targetIP net.IP, timeout time.Duration) (bool, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case packet, ok := <-packetChan:
			if !ok {
				return false, fmt.Errorf("packet channel closed")
			}
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if ipLayer == nil || tcpLayer == nil {
				continue
			}
			ip, _ := ipLayer.(*layers.IPv4)
			tcp, _ := tcpLayer.(*layers.TCP)

			// Verify the packet is from the target and destined to our source port.
			if !ip.SrcIP.Equal(targetIP) {
				continue
			}
			if tcp.DstPort != layers.TCPPort(srcPort) || tcp.SrcPort != layers.TCPPort(dstPort) {
				continue
			}
			if tcp.SYN && tcp.ACK {
				return true, nil
			} else if tcp.RST {
				return false, nil
			}
		case <-timer.C:
			return false, nil
		}
	}
}

// waitForResponse waits for a response packet
func waitForResponse(packets chan gopacket.Packet, srcPort, dstPort uint16, dstIP net.IP, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case packet := <-packets:
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if tcp.DstPort == layers.TCPPort(srcPort) && tcp.SrcPort == layers.TCPPort(dstPort) {
					return tcp.SYN && tcp.ACK
				}
			}
		case <-timer.C:
			return false
		}
	}
}

// Run performs the port scan for the given target.
func (ps *PortScanner) Run(target *models.TargetInfo, opts *models.Options) (*models.DTO, error) {
	// Prepare the results channel.
	resultsChan := make(chan int, ps.EndPort-ps.StartPort+1)

	// Set the network interface for SYN scanning.
	if opts.ScanMode == "syn" {
		ps.interfaceForSyn()
	}

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

// interfaceForSyn finds a suitable network interface for SYN scanning.
func (ps *PortScanner) interfaceForSyn() {
	// Find interface to be used for packets.
	devices, err := pcap.FindAllDevs()
	if err != nil {
		logrus.Fatalf("Error finding devices: %v", err)
	}
	for _, device := range devices {
		for _, addr := range device.Addresses {
			logrus.Debugf("Device %s with addresses %s", device.Description, addr)
			if ip := addr.IP; ip != nil && ip.To4() != nil && !ip.IsLoopback() && strings.Contains(device.Description, "Wi-Fi") {
				ps.Interface = device.Name
				break
			}
		}
		if ps.Interface != "" {
			break
		}
	}
	if ps.Interface == "" {
		logrus.Fatalf("No suitable network interface found")
	}
}

// scan starts the scanning procedure.
func (ps *PortScanner) scan(target string, mode string, resultsChan chan int) {
	// Set a global timeout based on the number of ports plus an extra buffer.
	totalTimeout := time.Duration(ps.EndPort-ps.StartPort)*ps.Timeout + 5*time.Second
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()

	// Create a channel for port numbers.
	portChan := make(chan int, 100)
	limiter := time.NewTicker(ps.RateLimit)
	defer limiter.Stop()

	var wg sync.WaitGroup
	var currentWorkers = int32(ps.MinWorkers)

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
