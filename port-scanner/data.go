package port_scanner

import (
	"github.com/google/gopacket/pcap"
	"net"
)

// NetworkInterface defines the network interface.
type NetworkInterface struct {
	Name    string                // Name defines the name of the network interface.
	MAC     net.IP                // MAC defines the MAC address of the network interface.
	Address pcap.InterfaceAddress // Address defines the IP address of the network interface.
}
