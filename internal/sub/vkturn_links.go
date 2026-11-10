// Copyright (c) 2026 LucX-UI Project.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// LucX-UI Component. Free for personal and educational use.
// Commercial use (including VPN resale) requires explicit written permission from the author.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package sub

import (
	"net"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/lucx/tunnel"
	wgutil "github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
)

// vkturnRelaysFor — включённые локальные релеи VK TURN, смотрящие в wg.
func vkturnRelaysFor(wg *model.Inbound) []*model.Inbound {
	if wg == nil || wg.Protocol != model.WireGuard || wg.NodeID != nil {
		return nil
	}
	var rows []*model.Inbound
	if err := database.GetDB().Where("protocol = ? AND enable = ?", model.Vkturn, true).Find(&rows).Error; err != nil {
		return nil
	}
	out := rows[:0]
	for _, ib := range rows {
		if cfg, ok := tunnel.VkturnConfigFromInbound(ib); ok && cfg.WgInboundId == wg.Id && ib.NodeID == nil {
			out = append(out, ib)
		}
	}
	return out
}

// vkturnLinks — ссылки vkturnproxy:// клиента email WireGuard-инбаунда wg
// (по одной на каждый релей, обычно один).
func (s *SubService) vkturnLinks(wg *model.Inbound, email string) []string {
	if email == "" {
		return nil
	}
	relays := vkturnRelaysFor(wg)
	if len(relays) == 0 {
		return nil
	}
	client, ok := s.clientForLink(wg, email)
	if !ok || client.PrivateKey == "" || len(client.AllowedIPs) == 0 {
		return nil
	}
	secretKey, _ := s.linkSettings(wg)["secretKey"].(string)
	serverPub, err := wgutil.PublicKeyFromPrivate(secretKey)
	if err != nil || serverPub == "" {
		return nil
	}
	var out []string
	for _, relay := range relays {
		cfg, _ := tunnel.VkturnConfigFromInbound(relay)
		host := cfg.SubHost
		if host == "" {
			host = s.resolveInboundAddress(relay)
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host == "" {
			continue
		}
		name := strings.TrimSpace(relay.Remark)
		if name == "" {
			name = "VK TURN"
		}
		link := tunnel.VkturnLink(tunnel.VkturnLinkInput{
			ServerName:    name,
			PeerAddress:   net.JoinHostPort(host, strconv.Itoa(relay.Port)),
			PrivateKey:    client.PrivateKey,
			PeerPublicKey: serverPub,
			PresharedKey:  client.PreSharedKey,
			TunnelAddress: client.AllowedIPs[0],
			VkHashes:      service.EffectiveVkHashes(email, cfg.VkHashes),
			DNS:           cfg.DNS,
			NumConns:      cfg.NumConnections,
		})
		if link != "" {
			out = append(out, link)
		}
	}
	return out
}

// vkturnInboundLinks — ссылки релея для всех клиентов его WG-инбаунда
// (кнопка «экспорт ссылок» на самом инбаунде vkturn).
func (s *SubService) vkturnInboundLinks(relay *model.Inbound) []string {
	cfg, ok := tunnel.VkturnConfigFromInbound(relay)
	if !ok || !relay.Enable {
		return nil
	}
	var wg model.Inbound
	if err := database.GetDB().First(&wg, cfg.WgInboundId).Error; err != nil {
		return nil
	}
	clients, err := s.clientsForLinkExport(&wg)
	if err != nil {
		return nil
	}
	var out []string
	for _, c := range clients {
		out = append(out, s.vkturnLinks(&wg, c.Email)...)
	}
	return out
}
