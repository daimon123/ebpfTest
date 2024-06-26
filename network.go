package main

import (
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
	"regexp"
)

// var netDeviceFilterRe = regexp.MustCompile(`^(enp\d+s\d+(f\d+)?|eth\d+|eno\d+|ens\d+|em\d+|bond\d+|p\d+p\d+|enx[0-9a-f]{12})`)
// 무선 네트워크  추가
var netDeviceFilterRe = regexp.MustCompile(`^(enp\d+s\d+(f\d+)?|eth\d+|eno\d+|ens\d+|em\d+|bond\d+|p\d+p\d+|enx[0-9a-f]{12}|wlp\d+s\d+(f\d+)?)$`)

func netDeviceFilter(name string) bool {
	return netDeviceFilterRe.MatchString(name)
}

type NetDeviceInfo struct {
	Name       string
	Up         float64
	IPPrefixes []netaddr.IPPrefix
	RxBytes    float64
	TxBytes    float64
	RxPackets  float64
	TxPackets  float64
}

func NetDevices() ([]NetDeviceInfo, error) {
	hostNs, err := proc.GetHostNetNs()
	if err != nil {
		return nil, err
	}
	defer hostNs.Close()
	h, err := netlink.NewHandleAt(hostNs)
	if err != nil {
		return nil, err
	}
	defer h.Delete()
	links, err := h.LinkList()
	if err != nil {
		return nil, err
	}
	var res []NetDeviceInfo
	for _, link := range links {
		attrs := link.Attrs()
		if !netDeviceFilter(attrs.Name) {
			continue
		}
		info := NetDeviceInfo{
			Name:      attrs.Name,
			RxBytes:   float64(attrs.Statistics.RxBytes),
			TxBytes:   float64(attrs.Statistics.TxBytes),
			RxPackets: float64(attrs.Statistics.RxPackets),
			TxPackets: float64(attrs.Statistics.TxPackets),
		}
		if attrs.OperState == netlink.OperUp {
			info.Up = 1
		}

		addrs, err := h.AddrList(link, unix.AF_UNSPEC)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			ip := addr.IP
			if ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsLinkLocalMulticast() {
				continue
			}
			if prefix, ok := netaddr.FromStdIPNet(addr.IPNet); ok {
				info.IPPrefixes = append(info.IPPrefixes, prefix)
			}
		}
		res = append(res, info)
	}
	return res, nil
}

// 루프백 네트워크와 사설네트워크 필터링
func whitelistNodeExternalNetworks() {
	netdevs, err := NetDevices()
	if err != nil {
		klog.Warningln("failed to get network interfaces:", err)
		return
	}
	for _, iface := range netdevs {
		for _, p := range iface.IPPrefixes {
			if p.IP().IsLoopback() || common.IsIpPrivate(p.IP()) {
				continue
			}
			// if the node has an external network IP, whitelist that network
			common.ConnectionFilter.WhitelistPrefix(p)
		}
	}

}
