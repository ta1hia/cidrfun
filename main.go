package main

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
)

const (
	BITMASK_32 = uint(4294967295)
)

var allFF = net.ParseIP("255.255.255.255").To4()

var AllowedNets = []string{
	"0.0.0.0/0",
}

var toblock = []string{"0.0.0.254", "221.198.4.1", "195.126.32.4"}

func x(s string) net.IP { return net.ParseIP(s) }

func IPRangeToCIDRs(a1, a2 net.IP) (r []*net.IPNet) {
	maxLen := 32
	a1 = a1.To4()
	a2 = a2.To4()
	for cmp(a1, a2) <= 0 {
		l := 32
		for l > 0 {
			m := net.CIDRMask(l-1, maxLen)
			if cmp(a1, MaskNetwork(a1, m)) != 0 || cmp(MaskHost(a1, m), a2) > 0 {
				break
			}
			l--
		}
		r = append(r, &net.IPNet{IP: a1, Mask: net.CIDRMask(l, maxLen)})
		a1 = MaskHost(a1, net.CIDRMask(l, maxLen))
		if cmp(a1, allFF) == 0 {
			break
		}
		a1 = next(a1)
	}
	return r
}

func next(ip net.IP) net.IP {
	n := len(ip)
	out := make(net.IP, n)
	copy := false
	for n > 0 {
		n--
		if copy {
			out[n] = ip[n]
			continue
		}
		if ip[n] < 255 {
			out[n] = ip[n] + 1
			copy = true
			continue
		}
		out[n] = 0
	}
	return out
}

// Compares IP bit by bit
//  0: ip1 == ip2
// -1: ip1 < ip2
//  1: ip1 > ip2
func cmp(ip1, ip2 net.IP) int {
	l := len(ip1)
	for i := 0; i < l; i++ {
		if ip1[i] == ip2[i] {
			continue
		}
		if ip1[i] < ip2[i] {
			return -1
		}
		return 1
	}
	return 0
}

func MaskNetwork(ip net.IP, mask net.IPMask) net.IP {
	return ip.Mask(mask)
}

func MaskHost(ip net.IP, mask net.IPMask) net.IP {
	n := len(ip)
	out := make(net.IP, n)
	for i := 0; i < n; i++ {
		out[i] = ip[i] | ^mask[i]
	}
	return out
}

func CIDRFirstUint(cidr *net.IPNet) uint {
	ipint := IPToInt(cidr.IP.String())
	prefixlen, _ := cidr.Mask.Size()
	netmask := (BITMASK_32 << uint(prefixlen)) & BITMASK_32
	return ipint & netmask
}

func CIDRLastUint(cidr *net.IPNet) uint {
	ipint := IPToInt(cidr.IP.String())
	prefixlen, _ := cidr.Mask.Size()
	hostmask := (1 << (32 - uint(prefixlen))) - 1
	return ipint | uint(hostmask)
}

func IPToInt(ip string) uint {
	octets := strings.Split(ip, ".")
	ipint := float64(0)
	for i := 0; i < 4; i++ {
		octet, _ := strconv.ParseFloat(octets[i], 64)
		ipint += octet * math.Pow(float64(256), float64(3-i))
	}
	return uint(ipint)
}

func IntToIP(ipint uint) string {
	return fmt.Sprintf("%d.%d.%d.%d", ipint>>24, ipint>>16&0xFF, ipint>>8&0xFF, ipint&0xFF)
}

func BlockIP(iptoblock string) {
	ip := x(iptoblock)
	ipint := IPToInt(iptoblock)
	for _, cidrstr := range AllowedNets {
		_, cidr, _ := net.ParseCIDR(cidrstr)
		if cidr.Contains(ip) {
			//process
			start := x(IntToIP(CIDRFirstUint(cidr)))
			end := x(IntToIP(CIDRLastUint(cidr)))
			ipend := x(IntToIP(ipint - 1))
			ipstart := x(IntToIP(ipint + 1))

			nets1 := IPRangeToCIDRs(start, ipend)
			fmt.Println(nets1)
			nets2 := IPRangeToCIDRs(ipstart, end)
			fmt.Println(nets2)
		}
	}
	//If iptoblock is not in 'AllowedNets', its already being blocked
}

func main() {

	for _, b := range toblock {
		fmt.Println("blocking " + b)
		BlockIP(b)
	}

	//221.198.0.0/16

}
