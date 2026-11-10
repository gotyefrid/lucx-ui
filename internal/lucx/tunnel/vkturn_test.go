// Copyright (c) 2026 LucX-UI Project.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// LucX-UI Component. Free for personal and educational use.
// Commercial use (including VPN resale) requires explicit written permission from the author.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package tunnel

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestVkturnLinkPayload(t *testing.T) {
	link := VkturnLink(VkturnLinkInput{
		ServerName: "iOS", PeerAddress: "1.2.3.4:56100",
		PrivateKey: "priv=", PeerPublicKey: "pub=", TunnelAddress: "10.0.0.2/32",
		VkHashes: "h1, h2", DNS: "1.1.1.1", NumConns: 30,
	})
	const prefix = "vkturnproxy://import?data="
	if !strings.HasPrefix(link, prefix) {
		t.Fatalf("link %q", link)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(link, prefix))
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Version  int            `json:"version"`
		Type     string         `json:"type"`
		Settings map[string]any `json:"settings"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	s := payload.Settings
	if payload.Version != 1 || payload.Type != "connection" {
		t.Fatalf("header %+v", payload)
	}
	if s["vkLink"] != "https://vk.ru/call/join/h1\nhttps://vk.ru/call/join/h2" {
		t.Fatalf("vkLink %q", s["vkLink"])
	}
	if s["useSrtp"] != true || s["useWrapA"] != false || s["useCsqtt"] != false || s["serverName"] != "iOS" {
		t.Fatalf("mode fields %+v", s)
	}
	if _, ok := s["presharedKey"]; ok {
		t.Fatal("empty PSK must be omitted")
	}
	if VkturnLink(VkturnLinkInput{PeerAddress: "x:1", PrivateKey: "a", PeerPublicKey: "b", TunnelAddress: "c"}) != "" {
		t.Fatal("no hashes must yield no link")
	}
}

func TestVkturnInstance(t *testing.T) {
	ib := &model.Inbound{Id: 5, Protocol: model.Vkturn, Enable: true, Port: 56100, Settings: `{"wgInboundId":3}`}
	wg := &model.Inbound{Id: 3, Protocol: model.WireGuard, Enable: true, Port: 51820}
	inst, ok := VkturnInstanceFromInbound(ib, wg)
	if !ok || !inst.Enabled || strings.Join(inst.Args, " ") != "-listen 0.0.0.0:56100 -connect 127.0.0.1:51820 -srtp" {
		t.Fatalf("inst %+v", inst)
	}
	wg.Enable = false
	if inst, _ := VkturnInstanceFromInbound(ib, wg); inst.Enabled {
		t.Fatal("disabled WG inbound must stop the relay")
	}
	if inst, _ := VkturnInstanceFromInbound(ib, nil); inst.Enabled {
		t.Fatal("missing WG inbound must stop the relay")
	}
}
