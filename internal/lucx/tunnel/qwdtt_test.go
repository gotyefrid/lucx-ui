// Copyright (c) 2025 LucX-UI Project.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// LucX-UI Component. Free for personal and educational use.
// Commercial use (including VPN resale) requires explicit written permission from the author.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package tunnel

import (
	"strings"
	"testing"
)

func TestDefaultQwdttConfig(t *testing.T) {
	cfg := DefaultQwdttConfig()
	if cfg.ListenAddr != "0.0.0.0:56000" || cfg.WGPort != 56001 {
		t.Fatalf("defaults = %+v", cfg)
	}
	if cfg.DNS != "8.8.8.8" || cfg.ClientPort != 9000 || cfg.Workers != 16 {
		t.Fatalf("defaults = %+v", cfg)
	}
}

func TestQwdttValidate(t *testing.T) {
	base := func() QwdttConfig {
		return DefaultQwdttConfig()
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*QwdttConfig)
	}{
		{"bad listen", func(c *QwdttConfig) { c.ListenAddr = "no-port" }},
		{"bad wg port", func(c *QwdttConfig) { c.WGPort = 0 }},
		{"empty dns", func(c *QwdttConfig) { c.DNS = " " }},
		{"dns with port", func(c *QwdttConfig) { c.DNS = "8.8.8.8:53" }},
		{"bad raw", func(c *QwdttConfig) { c.ListenRaw = "bad" }},
		{"bad workers", func(c *QwdttConfig) { c.Workers = 100 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestQwdttBuildArgs(t *testing.T) {
	cfg := DefaultQwdttConfig()
	cfg.Password = "s3cret"
	cfg.ConfigDir = "/var/lib/qwdtt"
	args := cfg.BuildArgs()
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "/var/lib/qwdtt") {
		t.Errorf("configDir outside workDir must be ignored: %v", args)
	}
	for _, want := range []string{
		"-listen 0.0.0.0:56000",
		"-wg-port 56001",
		"-password s3cret",
		"-dns 8.8.8.8",
		"-listen-raw 0.0.0.0:56003",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q: %v", want, args)
		}
	}
	// Empty listen-raw omits the flag.
	cfg.ListenRaw = ""
	joined = strings.Join(cfg.BuildArgs(), " ")
	if strings.Contains(joined, "-listen-raw") {
		t.Errorf("empty listen-raw must omit flag: %s", joined)
	}
}

func TestQwdttEnsureSubHost(t *testing.T) {
	cfg := DefaultQwdttConfig()
	cfg.ListenAddr = "0.0.0.0:56000"
	cfg.SubHost = "9.9.9.9:56000"
	got := cfg.EnsureSubHost()
	if got.SubHost != "9.9.9.9:56000" {
		t.Fatalf("EnsureSubHost overwrote existing: %q", got.SubHost)
	}
	cfg.SubHost = ""
	got = cfg.EnsureSubHost()
	if got.SubHost != "" && !strings.HasSuffix(got.SubHost, ":56000") {
		t.Fatalf("EnsureSubHost filled badly: %q", got.SubHost)
	}
}

func TestQwdttClientURI(t *testing.T) {
	cfg := DefaultQwdttConfig()
	cfg.Password = "pass"
	cfg.SubHost = "1.2.3.4:56000"
	cfg.VkHashes = "hash1,hash2"
	cfg.Remark = "Home"
	got := cfg.ClientURI()
	if !strings.HasPrefix(got, "qwdtt://config?") {
		t.Fatalf("URI = %q", got)
	}
	for _, want := range []string{"name=Home", "peer=1.2.3.4%3A56000", "pass=pass", "hashes=hash1%2Chash2", "workers=16", "port=9000"} {
		if !strings.Contains(got, want) {
			t.Errorf("URI missing %q: %s", want, got)
		}
	}
	if strings.ContainsAny(got, "\r\n") || strings.Contains(got, "\nwdtt://") {
		t.Fatalf("ClientURI must be a single qwdtt:// line, got %q", got)
	}
	cfg.SubHost = ""
	if cfg.ClientURI() != "" {
		t.Fatal("empty peer must yield empty URI")
	}
}

func TestQwdttLegacyURI(t *testing.T) {
	cfg := DefaultQwdttConfig()
	cfg.Password = "pass"
	cfg.SubHost = "1.2.3.4:56000"
	cfg.VkHashes = "abc"
	got := cfg.LegacyURI()
	want := "wdtt://1.2.3.4:56000:56001:9000:pass:abc"
	if got != want {
		t.Fatalf("LegacyURI = %q, want %q", got, want)
	}
}

func TestQwdttSubscription(t *testing.T) {
	cfg := DefaultQwdttConfig()
	cfg.Password = "pass"
	cfg.SubHost = "1.2.3.4:56000"
	cfg.VkHashes = "h1"
	sub, err := cfg.Subscription()
	if err != nil {
		t.Fatal(err)
	}
	if sub.Version != 1 || len(sub.Profiles) != 1 {
		t.Fatalf("sub = %+v", sub)
	}
	if sub.Profiles[0].Password != "pass" || sub.Profiles[0].Peer != "1.2.3.4:56000" {
		t.Fatalf("profile = %+v", sub.Profiles[0])
	}
	raw, err := cfg.SubscriptionJSON()
	if err != nil || !strings.Contains(raw, `"password": "pass"`) {
		t.Fatalf("json = %q err=%v", raw, err)
	}
}

func TestQwdttEnsurePassword(t *testing.T) {
	cfg := DefaultQwdttConfig()
	got, err := cfg.EnsurePassword()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Password) != 16 {
		t.Fatalf("password len = %d", len(got.Password))
	}
	keep := got.Password
	got2, _ := got.EnsurePassword()
	if got2.Password != keep {
		t.Fatal("EnsurePassword must keep existing")
	}
}

func TestQwdttNameRegistry(t *testing.T) {
	if !Qwdtt.Valid() || Qwdtt.DisplayName() != "qWDTT" {
		t.Fatalf("Qwdtt registry broken")
	}
	if got := Qwdtt.BinaryName(); !strings.HasPrefix(got, "qwdtt-") {
		t.Fatalf("BinaryName = %q", got)
	}
	all := All()
	if len(all) != 19 || all[18] != Vkturn || all[2] != Qwdtt || all[3] != Csqtt || all[4] != Masterdns || all[5] != Aivpn || all[6] != Mieru || all[7] != TrustTunnel || all[8] != Anytls || all[9] != Tproxy || all[12] != MtprotoZig || all[13] != TproxyCaddy || all[14] != Cover || all[15] != Gateway || all[16] != Openflux || all[17] != Wgosocks {
		t.Fatalf("All() = %v", all)
	}
}

func TestQwdttWithPeerHost(t *testing.T) {
	cfg := DefaultQwdttConfig()
	cfg = cfg.WithPeerHost("10.1.2.3")
	if cfg.SubHost != "10.1.2.3:56000" {
		t.Fatalf("SubHost = %q", cfg.SubHost)
	}
	if cfg.WithPeerHost("").SubHost != cfg.SubHost {
		t.Fatal("empty host must not clear SubHost")
	}
	v6 := DefaultQwdttConfig().WithPeerHost("2001:db8::1")
	if v6.SubHost != "[2001:db8::1]:56000" {
		t.Fatalf("ipv6 SubHost = %q", v6.SubHost)
	}
}

func TestQwdttValidateSubnets(t *testing.T) {
	cases := []struct {
		name, wg, raw, wantErr string
	}{
		{name: "defaults", wg: QwdttDefaultWGSubnet, raw: QwdttDefaultRawSubnet},
		{name: "custom /24 pair", wg: "192.168.77.0/24", raw: "172.20.0.0/20"},
		{name: "not cidr", wg: "10.80.0.1", raw: QwdttDefaultRawSubnet, wantErr: "wgSubnet must be an IPv4 CIDR"},
		{name: "ipv6", wg: QwdttDefaultWGSubnet, raw: "fd00::/64", wantErr: "rawSubnet must be an IPv4 CIDR"},
		{name: "host bits set", wg: "10.80.5.0/16", raw: QwdttDefaultRawSubnet, wantErr: "wgSubnet must be a network address (10.80.0.0/16)"},
		{name: "public range", wg: "8.8.0.0/16", raw: QwdttDefaultRawSubnet, wantErr: "wgSubnet must be a private range"},
		{name: "too wide", wg: "10.0.0.0/8", raw: QwdttDefaultRawSubnet, wantErr: "wgSubnet prefix must be /16../24"},
		{name: "too narrow", wg: QwdttDefaultWGSubnet, raw: "10.70.0.0/25", wantErr: "rawSubnet prefix must be /16../24"},
		{name: "wg overlaps raw", wg: "10.70.0.0/24", raw: QwdttDefaultRawSubnet, wantErr: "wgSubnet 10.70.0.0/24 overlaps rawSubnet 10.70.0.0/16"},
		{name: "overlaps csqtt", wg: "10.66.0.0/16", raw: QwdttDefaultRawSubnet, wantErr: "wgSubnet 10.66.0.0/16 overlaps CSQTT 10.66.67.0/24"},
		{name: "overlaps panel tun band", wg: "10.253.0.0/16", raw: QwdttDefaultRawSubnet, wantErr: "wgSubnet 10.253.0.0/16 overlaps panel tunnel range 10.200.0.0-10.255.255.255"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultQwdttConfig()
			cfg.WGSubnet, cfg.RawSubnet = tc.wg, tc.raw
			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("valid subnets rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestQwdttBuildArgsSubnets(t *testing.T) {
	cfg := DefaultQwdttConfig()
	joined := strings.Join(cfg.BuildArgs(), " ")
	for _, want := range []string{"-wg-subnet 10.68.0.0/16", "-raw-subnet 10.70.0.0/16"} {
		if !strings.Contains(joined, want) {
			t.Errorf("default args missing %q: %s", want, joined)
		}
	}
	cfg.WGSubnet, cfg.RawSubnet = "192.168.77.0/24", "172.20.0.0/20"
	joined = strings.Join(cfg.BuildArgs(), " ")
	for _, want := range []string{"-wg-subnet 192.168.77.0/24", "-raw-subnet 172.20.0.0/20"} {
		if !strings.Contains(joined, want) {
			t.Errorf("custom args missing %q: %s", want, joined)
		}
	}
}

// The form posts "" for an untouched field; Merge must restore the defaults
// or the sidecar would get an empty -wg-subnet and refuse to start.
func TestQwdttMergeBlankSubnets(t *testing.T) {
	cfg := QwdttConfig{WGSubnet: "", RawSubnet: "  "}.Merge()
	if cfg.WGSubnet != QwdttDefaultWGSubnet || cfg.RawSubnet != QwdttDefaultRawSubnet {
		t.Fatalf("merged subnets = %q / %q", cfg.WGSubnet, cfg.RawSubnet)
	}
	cfg = QwdttConfig{WGSubnet: " 192.168.77.0/24 "}.Merge()
	if cfg.WGSubnet != "192.168.77.0/24" {
		t.Fatalf("custom subnet not trimmed: %q", cfg.WGSubnet)
	}
}
