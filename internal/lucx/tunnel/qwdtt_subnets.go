// Copyright (c) 2025 LucX-UI Project.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// LucX-UI Component. Free for personal and educational use.
// Commercial use (including VPN resale) requires explicit written permission from the author.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package tunnel

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Defaults match the bundled sidecar's -wg-subnet / -raw-subnet
// (third_party/patches/qwdtt-subnet.patch).
const (
	QwdttDefaultWGSubnet  = "10.68.0.0/16"
	QwdttDefaultRawSubnet = "10.70.0.0/16"
)

// The panel derives /30 TUN gateways (10.250-10.254) and AIVPN pools
// (10.200-10.253) from inbound ids: 10.200.0.0-10.255.255.255 is off limits.
var qwdttPanelTunnelBand = []netip.Prefix{
	netip.MustParsePrefix("10.200.0.0/13"),
	netip.MustParsePrefix("10.208.0.0/12"),
	netip.MustParsePrefix("10.224.0.0/11"),
}

func parseQwdttSubnet(field, value string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil || !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("qwdtt: %s must be an IPv4 CIDR like 10.68.0.0/16, got %q", field, value)
	}
	if p.Masked() != p {
		return netip.Prefix{}, fmt.Errorf("qwdtt: %s must be a network address (%s)", field, p.Masked())
	}
	if !p.Addr().IsPrivate() {
		return netip.Prefix{}, fmt.Errorf("qwdtt: %s must be a private range (10/8, 172.16/12, 192.168/16)", field)
	}
	if p.Bits() < 16 || p.Bits() > 24 {
		return netip.Prefix{}, fmt.Errorf("qwdtt: %s prefix must be /16../24", field)
	}
	if csqtt := netip.MustParsePrefix(csqttSubnet); p.Overlaps(csqtt) {
		return netip.Prefix{}, fmt.Errorf("qwdtt: %s %s overlaps CSQTT %s", field, p, csqtt)
	}
	if slices.ContainsFunc(qwdttPanelTunnelBand, p.Overlaps) {
		return netip.Prefix{}, fmt.Errorf("qwdtt: %s %s overlaps panel tunnel range 10.200.0.0-10.255.255.255", field, p)
	}
	return p, nil
}

func validateQwdttSubnets(wg, raw string) error {
	w, err := parseQwdttSubnet("wgSubnet", wg)
	if err != nil {
		return err
	}
	r, err := parseQwdttSubnet("rawSubnet", raw)
	if err != nil {
		return err
	}
	if w.Overlaps(r) {
		return fmt.Errorf("qwdtt: wgSubnet %s overlaps rawSubnet %s", w, r)
	}
	return nil
}
