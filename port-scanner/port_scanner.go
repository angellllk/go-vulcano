package port_scanner

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
	"github.com/sirupsen/logrus"
	"go-vulcano/models"
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
func (ps *PortScanner) Configure(cfg models.PortScannerConfig) {
	ps.StartPort = cfg.StartPort
	ps.EndPort = cfg.EndPort
	ps.Timeout = time.Millisecond * time.Duration(cfg.Timeout)
	ps.MinWorkers = cfg.MinWorkers
	ps.MaxWorkers = cfg.MaxWorkers
	ps.IdleTimeout = time.Millisecond * time.Duration(cfg.IdleTimeout)
	ps.RateLimit = time.Millisecond * time.Duration(cfg.RateLimit)
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
	devices, err := pcap.FindAllDevs()
	if err != nil {
		logrus.Fatalf("Error finding devices: %v", err)
	}

	for _, device := range devices {
		for _, addr := range device.Addresses {
			if isValidIP(addr) && isDesiredInterface(device) {
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

// isValidIP checks if the given interface address is a valid IPv4 address.
func isValidIP(addr pcap.InterfaceAddress) bool {
	ip := addr.IP
	return ip != nil && ip.To4() != nil && !ip.IsLoopback()
}

// isDesiredInterface checks if the given interface is a desired one for SYN scanning.
func isDesiredInterface(device pcap.Interface) bool {
	if runtime.GOOS == "windows" {
		return !strings.Contains(device.Description, "Virtual") && (strings.Contains(device.Description, "Wi-Fi") || strings.Contains(device.Description, "Ethernet"))
	}

	return strings.HasPrefix(device.Name, "wlp") || strings.HasPrefix(device.Name, "wlan") ||
		strings.HasPrefix(device.Name, "enp") || strings.HasPrefix(device.Name, "eth")
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

	var iface *net.Interface

	// TODO: for local testing on Windows, will delete later
	if runtime.GOOS == "windows" {
		iface, err = net.InterfaceByName("Wi-Fi")
		if err != nil {
			return err
		}
	} else {
		iface, err = net.InterfaceByName(ps.Interface.Name)
		if err != nil {
			return err
		}
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
	ps.scan(target.IP, opts.ScanMode, resultsChan)

	// Collect and sort open ports.
	var openPorts []int
	for port := range resultsChan {
		openPorts = append(openPorts, port)
	}
	sort.Ints(openPorts)
	logrus.Infof("Open ports on %s (%s): %v", target.Domain, target.IP.String(), openPorts)

	return &models.DTO{Ports: openPorts}, nil
}

// scan starts the scanning procedure.
func (ps *PortScanner) scan(target net.IP, mode string, resultsChan chan int) {
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
		limiter = time.NewTicker(1 * time.Nanosecond)
	}

	// Spawn the initial pool of workers.
	for i := 0; i < ps.MinWorkers; i++ {
		wg.Add(1)
		ps.spawnWorker(mode, target, &currentWorkers, portChan, resultsChan, ctx, limiter, &wg)
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
					ps.spawnWorker(mode, target, &currentWorkers, portChan, resultsChan, ctx, limiter, &wg)
				}
			}
		}
		close(portChan)
	}()

	wg.Wait()
	close(resultsChan)
}

func (ps *PortScanner) spawnWorker(mode string, target net.IP, currentWorkers *int32, portChan chan int, resultsChan chan int, ctx context.Context, limiter *time.Ticker, wg *sync.WaitGroup) {
	if mode == "tcp" {
		go ps.tcpWorker(target, currentWorkers, portChan, resultsChan, ctx, limiter, wg)
	} else {
		go ps.synWorker(target, currentWorkers, portChan, resultsChan, ctx, limiter, wg)
	}
}

// tcpWorker scans a target port using a TCP connection.
func (ps *PortScanner) tcpWorker(target net.IP, currentWorkers *int32, portChan chan int, resultsChan chan int, ctx context.Context, limiter *time.Ticker, wg *sync.WaitGroup) {
	ps.worker(target, currentWorkers, portChan, resultsChan, ctx, limiter, wg, ps.dialTcp)
}

// synWorker scans a target port using a SYN packet.
func (ps *PortScanner) synWorker(target net.IP, currentWorkers *int32, portChan chan int, resultsChan chan int, ctx context.Context, limiter *time.Ticker, wg *sync.WaitGroup) {
	ps.worker(target, currentWorkers, portChan, resultsChan, ctx, limiter, wg, ps.sendSyn)
}

// worker is a generic worker function that scans ports using a specified function.
func (ps *PortScanner) worker(target net.IP, currentWorkers *int32, portChan chan int, resultsChan chan int, ctx context.Context, limiter *time.Ticker, wg *sync.WaitGroup, scanFunc func(target net.IP, port int, ctx context.Context, resultsChan chan int)) {
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
			<-limiter.C
			resetTimer(idleTimer, ps.IdleTimeout)
			scanFunc(target, port, ctx, resultsChan)

		case <-idleTimer.C:
			atomic.AddInt32(currentWorkers, -1)
			return
		}
	}
}

func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// dialTcp dials the target port and sends the result to the results channel.
func (ps *PortScanner) dialTcp(target net.IP, port int, ctx context.Context, resultsChan chan int) {
	address := fmt.Sprintf("%s:%d", target.String(), port)
	// Create a per-dial context with the specified timeout.
	dialCtx, cancelDial := context.WithTimeout(ctx, ps.Timeout)
	defer cancelDial()

	// Dial the target port.
	startTime := time.Now()

	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", address)

	duration := time.Since(startTime)

	// Check if the port is open.
	if err == nil {
		resultsChan <- port
		conn.Close()
		logrus.Debugf("Port %d open (in %v)", port, duration)
	} else {
		logrus.Tracef("Port %d closed (error: %v, in %v)", port, err, duration)
	}
}

// sendSyn sends a SYN packet to the target port and waits for a response.
func (ps *PortScanner) sendSyn(target net.IP, port int, ctx context.Context, resultsChan chan int) {
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
	filter := fmt.Sprintf("tcp and src host %s and tcp dst port %d", target.String(), srcPort)
	if err = handle.SetBPFFilter(filter); err != nil {
		logrus.Warnf("Failed to set BPF filter: %v", err)
	}

	packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

	// Build SYN packet
	rawPacket, err := ps.buildSYNPacket(ps.Interface.Address.IP, target, srcPort, port)
	if err != nil {
		logrus.Errorf("Failed to build SYN packet: %v", err)
		return
	}

	// Send SYN packet
	if err = handle.WritePacketData(rawPacket); err != nil {
		logrus.Errorf("Failed to send packet: %v", err)
		return
	}

	select {
	case <-ctx.Done():
		logrus.Errorf("context cancelled or timed out for port %d", port)
		return
	default:
		ps.waitForResponse(packets, srcPort, uint16(port), ps.Timeout, resultsChan)
	}
}

// buildSYNPacket constructs and serializes a SYN packet with the given IPs and ports.
func (ps *PortScanner) buildSYNPacket(srcIP, dstIP net.IP, srcPort uint16, dstPort int) ([]byte, error) {
	iface, err := net.InterfaceByName(ps.Interface.Name)
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
	if err = gopacket.SerializeLayers(buffer, opts, ethLayer, ipLayer, tcpLayer); err != nil {
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
		case packet, ok := <-packets:
			if !ok {
				return false
			}

			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if tcp.DstPort == layers.TCPPort(srcPort) && tcp.SrcPort == layers.TCPPort(dstPort) && tcp.SYN && tcp.ACK {
					resultsChan <- int(dstPort)
					return true
				}
			}
		case <-timer.C:
			return false
		}
	}
}
