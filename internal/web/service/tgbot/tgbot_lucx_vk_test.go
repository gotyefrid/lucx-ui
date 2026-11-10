// Copyright (c) 2026 LucX-UI Project.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// LucX-UI Component. Free for personal and educational use.
// Commercial use (including VPN resale) requires explicit written permission from the author.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package tgbot

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
)

func seedVkInbound(t *testing.T, protocol model.Protocol, port int, settings string) int {
	t.Helper()
	ib := &model.Inbound{
		UserId: 1, Tag: fmt.Sprintf("vk-%s-%d", protocol, port), Remark: string(protocol),
		Port: port, Protocol: protocol, Enable: true, Settings: settings,
	}
	if err := database.GetDB().Create(ib).Error; err != nil {
		t.Fatalf("seed %s inbound: %v", protocol, err)
	}
	return ib.Id
}

// seedRelayedWireGuard is the iOS setup: a WireGuard inbound behind a VK TURN relay.
func seedRelayedWireGuard(t *testing.T) int {
	t.Helper()
	wg := seedVkInbound(t, model.WireGuard, 51820, `{"mtu":1420,"secretKey":"","peers":[]}`)
	seedVkInbound(t, model.Vkturn, 56100, fmt.Sprintf(`{"wgInboundId":%d}`, wg))
	return wg
}

func draftOffersVk(t *testing.T, tb *Tgbot, draft *clientDraft) bool {
	t.Helper()
	markup, _ := json.Marshal(tb.getCommonClientButtons(draft))
	return strings.Contains(string(markup), "add_client_ch_default_vk")
}

// The call hash only means something to wdtt/CSQTT/iOS-relay clients; anywhere
// else the button would store a value nothing reads.
func TestWizardOffersVkHashesOnlyForVkTunnels(t *testing.T) {
	localizeWithRealBundle(t)
	tb, _ := newScreenTgbot(t, false)
	initReportDB(t)
	vless := seedVkInbound(t, model.VLESS, 443, `{"clients":[]}`)
	bareWG := seedVkInbound(t, model.WireGuard, 51821, `{"mtu":1420,"secretKey":"","peers":[]}`)
	qwdtt := seedVkInbound(t, model.Qwdtt, 56000, `{}`)
	relayed := seedRelayedWireGuard(t)

	for name, tc := range map[string]struct {
		ids  []int
		want bool
	}{
		"xray only":            {[]int{vless}, false},
		"wireguard, no relay":  {[]int{bareWG}, false},
		"qwdtt":                {[]int{vless, qwdtt}, true},
		"wireguard with relay": {[]int{relayed}, true},
	} {
		if got := draftOffersVk(t, tb, &clientDraft{email: "x", receiverInboundIDs: tc.ids}); got != tc.want {
			t.Errorf("%s: VK button offered = %v, want %v", name, got, tc.want)
		}
	}
}

func TestDraftVkInputValidatesAndClears(t *testing.T) {
	draft := &clientDraft{}
	if err := setDraftVkHashes(draft, "https://vk.com/call/join/AbC_1, xyz-2"); err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
	if draft.vkHashes != "AbC_1,xyz-2" {
		t.Fatalf("draft hashes = %q, want the normalized hashes", draft.vkHashes)
	}
	if err := setDraftVkHashes(draft, "bad hash!"); err == nil {
		t.Fatal("invalid hash accepted")
	}
	if draft.vkHashes != "AbC_1,xyz-2" {
		t.Fatalf("rejected input changed the draft to %q", draft.vkHashes)
	}
	if err := setDraftVkHashes(draft, "-"); err != nil || draft.vkHashes != "" {
		t.Fatalf("'-' did not clear the hashes: %q, %v", draft.vkHashes, err)
	}
}

// Hashes saved before the client exists are swept by the member sync, so the
// bot must store them only after Create, and under the created email.
func TestSubmitAddClientStoresVkHashes(t *testing.T) {
	localizeWithRealBundle(t)
	tb, _ := newScreenTgbot(t, false)
	initReportDB(t)
	wg := seedRelayedWireGuard(t)

	draft := &clientDraft{email: "ios-new", subID: "subiosnew1234567", enable: true, receiverInboundIDs: []int{wg}}
	if err := setDraftVkHashes(draft, "https://vk.com/call/join/CallHash_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := tb.SubmitAddClient(draft); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if got := service.ClientVkHashes("ios-new"); got != "CallHash_1" {
		t.Fatalf("stored VK hashes = %q, want CallHash_1", got)
	}
}

func TestClientCardEditsVkHashesOfTunnelClient(t *testing.T) {
	localizeWithRealBundle(t)
	tb, _ := newScreenTgbot(t, false)
	initReportDB(t)
	wg := seedRelayedWireGuard(t)
	vless := seedVkInbound(t, model.VLESS, 443, `{"clients":[]}`)
	for email, ib := range map[string]int{"ios-card": wg, "vless-card": vless} {
		draft := &clientDraft{email: email, subID: "sub" + email + "0000000", enable: true, receiverInboundIDs: []int{ib}}
		if _, err := tb.SubmitAddClient(draft); err != nil {
			t.Fatalf("seed client %s: %v", email, err)
		}
	}

	card := func(email string) string {
		markup, _ := json.Marshal(tb.clientRows(email))
		return string(markup)
	}
	if !strings.Contains(card("ios-card"), tb.encodeQuery("client_vk ios-card")) {
		t.Fatal("the card of an iOS-relay client offers no VK hash button")
	}
	if strings.Contains(card("vless-card"), "client_vk") {
		t.Fatal("the card of a plain VLESS client offers a VK hash button")
	}

	if err := tb.saveClientVkHashes("ios-card", "https://vk.ru/call/join/New_2"); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := service.ClientVkHashes("ios-card"); got != "New_2" {
		t.Fatalf("stored = %q, want New_2", got)
	}
	if err := tb.saveClientVkHashes("ios-card", "bad#hash"); err == nil {
		t.Fatal("invalid hash saved")
	}
	if err := tb.saveClientVkHashes("ios-card", "-"); err != nil || service.ClientVkHashes("ios-card") != "" {
		t.Fatalf("'-' did not clear: %q, %v", service.ClientVkHashes("ios-card"), err)
	}
}
