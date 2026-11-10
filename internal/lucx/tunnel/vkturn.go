// Copyright (c) 2026 LucX-UI Project.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// LucX-UI Component. Free for personal and educational use.
// Commercial use (including VPN resale) requires explicit written permission from the author.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package tunnel

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

// Vkturn — серверная часть anton48/vk-turn-proxy (ветка add-server-srtp-layer,
// GPL-3.0, внешний процесс) для iOS-приложения anton48/vk-turn-proxy-ios.
// Это UDP-релей: принимает DTLS-SRTP сессии через VK TURN и отдаёт
// WireGuard-пакеты в WireGuard-инбаунд панели (-connect 127.0.0.1:<порт>).
// Своих пользователей нет: клиенты — пиры выбранного WireGuard-инбаунда.
const Vkturn Name = "vkturn"

const (
	vkturnDefaultPort    = 56100
	vkturnDefaultDNS     = "1.1.1.1"
	vkturnDefaultConns   = 30
	vkturnMaxConns       = 50
	vkturnCallJoinBase   = "https://vk.ru/call/join/"
	vkturnSchemaVersion  = 1
	vkturnLinkTypeConfig = "connection"
)

// VkturnConfig — настройки инбаунда VK TURN (iOS). Публичный UDP-порт —
// inbound.Port.
type VkturnConfig struct {
	// WgInboundId — WireGuard-инбаунд (Xray), в который релей отдаёт пакеты.
	WgInboundId int `json:"wgInboundId"`
	// SubHost — адрес сервера для клиентов (IP или домен, без порта);
	// пусто = адрес панели/инбаунда.
	SubHost string `json:"subHost"`
	// VkHashes — хеши VK-звонков по умолчанию (у клиента могут быть свои).
	VkHashes string `json:"vkHashes"`
	// DNS — DNS внутри туннеля для iOS-приложения.
	DNS string `json:"dns"`
	// NumConnections — число TURN-аллокаций в приложении (1..50).
	NumConnections int `json:"numConnections"`
}

// DefaultVkturnConfig — значения по умолчанию.
func DefaultVkturnConfig() VkturnConfig {
	return VkturnConfig{DNS: vkturnDefaultDNS, NumConnections: vkturnDefaultConns}
}

// Merge заполняет пустые поля значениями по умолчанию.
func (c VkturnConfig) Merge() VkturnConfig {
	def := DefaultVkturnConfig()
	if strings.TrimSpace(c.DNS) == "" {
		c.DNS = def.DNS
	}
	if c.NumConnections == 0 {
		c.NumConnections = def.NumConnections
	}
	return c
}

// Validate проверяет настройки и порт инбаунда.
func (c VkturnConfig) Validate(port int) error {
	if port < 1 || port > 65535 {
		return errors.New("vkturn: port must be in 1..65535")
	}
	if c.WgInboundId <= 0 {
		return errors.New("vkturn: choose the WireGuard inbound to relay to")
	}
	if c.NumConnections < 1 || c.NumConnections > vkturnMaxConns {
		return fmt.Errorf("vkturn: numConnections must be in 1..%d", vkturnMaxConns)
	}
	if h := strings.TrimSpace(c.SubHost); h != "" {
		if _, _, err := net.SplitHostPort(h); err == nil {
			return errors.New("vkturn: subHost is a host without port (the port is the inbound port)")
		}
	}
	return nil
}

// VkturnKey — ключ процесса в менеджере (по одному на инбаунд).
func VkturnKey(inboundID int) string {
	return fmt.Sprintf("vkturn-%d", inboundID)
}

// VkturnConfigFromInbound разбирает настройки инбаунда vkturn.
func VkturnConfigFromInbound(ib *model.Inbound) (VkturnConfig, bool) {
	if ib == nil || ib.Protocol != model.Vkturn {
		return VkturnConfig{}, false
	}
	cfg := DefaultVkturnConfig()
	if raw := strings.TrimSpace(ib.Settings); raw != "" && raw != "{}" {
		_ = json.Unmarshal([]byte(raw), &cfg)
	}
	return cfg.Merge(), true
}

// VkturnListenAddr — адрес, на котором слушает релей.
func VkturnListenAddr(ib *model.Inbound) string {
	host := strings.TrimSpace(ib.Listen)
	if host == "" {
		host = "0.0.0.0"
	}
	port := ib.Port
	if port <= 0 {
		port = vkturnDefaultPort
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// VkturnInstanceFromInbound строит процесс релея. wg — целевой WireGuard-
// инбаунд; без него (удалён, выключен, не тот протокол) релей не запускаем.
func VkturnInstanceFromInbound(ib, wg *model.Inbound) (Instance, bool) {
	cfg, ok := VkturnConfigFromInbound(ib)
	if !ok {
		return Instance{}, false
	}
	key := VkturnKey(ib.Id)
	off := Instance{Core: Vkturn, Key: key, Enabled: false}
	if !ib.Enable || cfg.Validate(ib.Port) != nil {
		return off, true
	}
	if wg == nil || wg.Protocol != model.WireGuard || !wg.Enable || wg.Port <= 0 || wg.Id != cfg.WgInboundId {
		return off, true
	}
	return Instance{
		Core:    Vkturn,
		Key:     key,
		Enabled: true,
		Args: []string{
			"-listen", VkturnListenAddr(ib),
			"-connect", net.JoinHostPort("127.0.0.1", strconv.Itoa(wg.Port)),
			"-srtp",
		},
	}, true
}

// VkturnLinkInput — данные одного WireGuard-пира для ссылки vkturnproxy://.
type VkturnLinkInput struct {
	ServerName    string
	PeerAddress   string // host:port релея
	PrivateKey    string
	PeerPublicKey string
	PresharedKey  string
	TunnelAddress string
	VkHashes      string
	DNS           string
	NumConns      int
}

// VkturnLink собирает ссылку vkturnproxy://import?data=<base64url(json)> в
// формате quick_link.py (schema version 1). Режим задаём явно (useSrtp=true,
// остальные false): импорт применяет тройку режимов целиком, иначе на
// устройстве остался бы прежний режим (WRAP-A/csqtt).
func VkturnLink(in VkturnLinkInput) string {
	hashes := NormalizeVkHashes(in.VkHashes)
	if in.PeerAddress == "" || in.PrivateKey == "" || in.PeerPublicKey == "" || in.TunnelAddress == "" || hashes == "" {
		return ""
	}
	calls := strings.Split(hashes, ",")
	for i, h := range calls {
		calls[i] = vkturnCallJoinBase + h
	}
	settings := map[string]any{
		"privateKey":     in.PrivateKey,
		"peerPublicKey":  in.PeerPublicKey,
		"tunnelAddress":  in.TunnelAddress,
		"vkLink":         strings.Join(calls, "\n"),
		"peerAddress":    in.PeerAddress,
		"dnsServers":     in.DNS,
		"numConnections": in.NumConns,
		"useDTLS":        true,
		"useWrap":        false,
		"wrapKeyHex":     "",
		"useSrtp":        true,
		"useUDP":         false,
		"useWrapA":       false,
		"useWrapS":       false,
		"useCsqtt":       false,
	}
	if in.PresharedKey != "" {
		settings["presharedKey"] = in.PresharedKey
	}
	if name := strings.TrimSpace(in.ServerName); name != "" {
		settings["serverName"] = name
	}
	payload := map[string]any{
		"version":  vkturnSchemaVersion,
		"type":     vkturnLinkTypeConfig,
		"settings": settings,
	}
	// json.Marshal сортирует ключи map — как sort_keys=True в quick_link.py.
	raw, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return "vkturnproxy://import?data=" + base64.RawURLEncoding.EncodeToString(raw)
}
