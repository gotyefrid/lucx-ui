// Copyright (c) 2026 LucX-UI Project.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// LucX-UI Component. Free for personal and educational use.
// Commercial use (including VPN resale) requires explicit written permission from the author.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/lucx/tunnel"
	"github.com/mhsanaei/3x-ui/v3/internal/util/common"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

const (
	// Сервер удаляет истёкший пароль вместе с устройствами, поэтому срок на
	// сервере держим максимальным и продлеваем, а срок клиента панели
	// применяем через deactivate/activate.
	qwdttServerDays     = 365
	qwdttRenewBelowDays = 300
	// limitIp == 0 (без ограничений) → столько устройств на пароль.
	qwdttUnlimitedDevices = 100
)

// vkHashRe — допустимый VK-хеш звонка (двоеточие/запятая сломали бы ссылки).
var vkHashRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// QwdttMemberService заводит на сервере qWDTT отдельный пароль на каждого
// клиента панели (инбаунд в режиме perClient) и держит его в соответствии
// с клиентом: включён/срок/лимит трафика, лимит устройств, VK-хеши.
type QwdttMemberService struct {
	mu sync.Mutex
}

var qwdttMemberSync QwdttMemberService

func GetQwdttMemberService() *QwdttMemberService { return &qwdttMemberSync }

// TriggerQwdttMemberSync запускает синхронизацию после изменения клиентов;
// периодический job остаётся страховкой, если qWDTT был недоступен.
func TriggerQwdttMemberSync() {
	done := database.BeginBackgroundDB()
	common.GoRecover("qwdtt-member-sync", func() {
		defer done()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := GetQwdttMemberService().SyncAll(ctx); err != nil {
			logger.Warning("qwdtt members immediate sync:", err)
		}
	})
}

// Password возвращает пароль клиента на сервере qWDTT.
func (s *QwdttMemberService) Password(inboundID int, email string) (string, bool) {
	var member model.QwdttMember
	err := database.GetDB().Where("inbound_id = ? AND client_email = ?", inboundID, email).First(&member).Error
	return member.Password, err == nil && strings.TrimSpace(member.Password) != ""
}

// ClientVkHashes — индивидуальные VK-хеши клиента ("" = не заданы).
func ClientVkHashes(email string) string {
	var row model.TunnelClientVk
	if err := database.GetDB().Where("client_email = ?", email).First(&row).Error; err != nil {
		return ""
	}
	return tunnel.NormalizeVkHashes(row.VkHashes)
}

// EffectiveVkHashes — хеши клиента, а если их нет, то хеши инбаунда.
func EffectiveVkHashes(email, inboundHashes string) string {
	if h := ClientVkHashes(email); h != "" {
		return h
	}
	return tunnel.NormalizeVkHashes(inboundHashes)
}

// SetClientVkHashes сохраняет индивидуальные VK-хеши клиента (пусто = сброс).
func SetClientVkHashes(email, hashes string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return errors.New("client email is empty")
	}
	hashes = tunnel.NormalizeVkHashes(hashes)
	for _, h := range strings.Split(hashes, ",") {
		if h != "" && !vkHashRe.MatchString(h) {
			return fmt.Errorf("invalid VK hash %q: only letters, digits, '-' and '_'", h)
		}
	}
	if hashes == "" {
		return database.GetDB().Where("client_email = ?", email).Delete(&model.TunnelClientVk{}).Error
	}
	row := &model.TunnelClientVk{ClientEmail: email, VkHashes: hashes}
	return database.GetDB().Where("client_email = ?", email).Assign(model.TunnelClientVk{VkHashes: hashes}).FirstOrCreate(row).Error
}

// SyncAll синхронизирует все локальные qWDTT-инбаунды в режиме perClient.
func (s *QwdttMemberService) SyncAll(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// VK-хеши удалённых/переименованных клиентов больше не нужны.
	database.GetDB().Where("client_email NOT IN (?)", database.GetDB().Model(&model.ClientRecord{}).Select("email")).
		Delete(&model.TunnelClientVk{})

	var inbounds []*model.Inbound
	if err := database.GetDB().Where("protocol = ?", model.Qwdtt).Find(&inbounds).Error; err != nil {
		return err
	}
	var firstErr error
	for _, inbound := range inbounds {
		cfg, ok := tunnel.QwdttConfigFromInbound(inbound)
		// Узлы (NodeID) не трогаем: admin API слушает только loopback узла.
		if !ok || !cfg.QwdttPerClientActive() || !inbound.Enable || inbound.NodeID != nil {
			continue
		}
		if err := s.syncInbound(ctx, inbound, cfg); err != nil {
			logger.Warning("qwdtt members: inbound", inbound.Id, "sync failed:", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

type qwdttWant struct {
	client     model.Client
	active     bool
	hashes     string
	maxDevices int
}

func (s *QwdttMemberService) syncInbound(ctx context.Context, inbound *model.Inbound, cfg tunnel.QwdttConfig) error {
	clients, err := (&ClientService{}).ListForInbound(nil, inbound.Id)
	if err != nil {
		return err
	}
	api, err := tunnel.NewQwdttAdminClient(cfg)
	if err != nil {
		return err
	}
	serverList, err := api.List(ctx)
	if err != nil {
		return err
	}
	byPass := make(map[string]tunnel.QwdttAdminPassword, len(serverList))
	byLabel := make(map[string]tunnel.QwdttAdminPassword, len(serverList))
	for _, p := range serverList {
		byPass[p.Password] = p
		if _, dup := byLabel[p.Label]; !dup && p.Label != "" {
			byLabel[p.Label] = p
		}
	}
	var rows []model.QwdttMember
	if err := database.GetDB().Where("inbound_id = ?", inbound.Id).Find(&rows).Error; err != nil {
		return err
	}
	rowByEmail := make(map[string]model.QwdttMember, len(rows))
	owned := make(map[string]bool, len(rows))
	for _, r := range rows {
		rowByEmail[r.ClientEmail] = r
		if r.Password != "" {
			owned[r.Password] = true
		}
	}

	now := time.Now()
	desired := make(map[string]struct{}, len(clients))
	var traffic []*xray.ClientTraffic
	var online []string
	var firstErr error
	for _, client := range clients {
		email := strings.TrimSpace(client.Email)
		if email == "" {
			continue
		}
		desired[email] = struct{}{}
		want := qwdttWant{
			client:     client,
			active:     clientWantsActive(client, now),
			hashes:     EffectiveVkHashes(email, cfg.VkHashes),
			maxDevices: client.LimitIP,
		}
		if want.maxDevices <= 0 {
			want.maxDevices = qwdttUnlimitedDevices
		}
		row, hasRow := rowByEmail[email]
		delta, isOnline, syncErr := s.syncMember(ctx, api, inbound.Id, want, row, hasRow, byPass, byLabel, owned)
		if syncErr != nil {
			logger.Warningf("qwdtt members: client %q: %v", email, syncErr)
			if firstErr == nil {
				firstErr = syncErr
			}
		}
		if delta != nil {
			traffic = append(traffic, delta)
		}
		if isOnline {
			online = append(online, email)
		}
	}

	// Клиент удалён или отвязан от инбаунда — удаляем его пароль на сервере.
	for _, r := range rows {
		if _, ok := desired[r.ClientEmail]; ok {
			continue
		}
		if _, onServer := byPass[r.Password]; r.Password != "" && onServer {
			if err := api.Delete(ctx, r.Password); err != nil && !tunnel.IsQwdttAdminStatus(err, http.StatusNotFound) {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
		}
		if err := database.GetDB().Delete(&model.QwdttMember{}, r.Id).Error; err != nil && firstErr == nil {
			firstErr = err
		}
	}

	tag := strings.TrimSpace(inbound.Tag)
	if len(traffic) > 0 {
		if _, _, err := (&InboundService{}).AddTraffic(nil, traffic); err != nil {
			logger.Warning("qwdtt members: add traffic failed:", err)
		}
		for _, t := range traffic {
			RecordLiveInbound(t.Email, tag, t.Up+t.Down, now.UnixMilli())
		}
	}
	if len(online) > 0 {
		(&InboundService{}).RefreshLocalOnlineClients(online, []string{tag})
	}
	return firstErr
}

// syncMember приводит пароль одного клиента к желаемому состоянию. Возвращает
// прирост трафика с прошлого опроса и признак «онлайн».
func (s *QwdttMemberService) syncMember(
	ctx context.Context,
	api *tunnel.QwdttAdminClient,
	inboundID int,
	want qwdttWant,
	row model.QwdttMember,
	hasRow bool,
	byPass, byLabel map[string]tunnel.QwdttAdminPassword,
	owned map[string]bool,
) (*xray.ClientTraffic, bool, error) {
	email := want.client.Email
	server, onServer := tunnel.QwdttAdminPassword{}, false
	if hasRow && row.Password != "" {
		server, onServer = byPass[row.Password]
	}
	fresh := false
	if !onServer {
		// Пароль, заведённый вручную (бот/перенос с wdtt) с label = email,
		// подхватываем: у клиента остаются рабочими уже выданные конфиги.
		if adopted, ok := byLabel[email]; ok && !owned[adopted.Password] {
			server, onServer = adopted, true
			owned[adopted.Password] = true
			if ClientVkHashes(email) == "" && adopted.VkHash != "" && tunnel.NormalizeVkHashes(adopted.VkHash) != want.hashes {
				if err := SetClientVkHashes(email, adopted.VkHash); err == nil {
					want.hashes = tunnel.NormalizeVkHashes(adopted.VkHash)
				}
			}
			logger.Infof("qwdtt members: adopted existing password %q for client %q", adopted.Label, email)
		} else {
			if want.hashes == "" {
				return nil, false, s.saveRow(inboundID, email, row, hasRow, "", 0, 0,
					"no VK hashes: set them on the client or the inbound")
			}
			created, err := api.Create(ctx, email, want.hashes, want.maxDevices, qwdttServerDays)
			if err != nil {
				msg := err.Error()
				if tunnel.IsQwdttAdminStatus(err, http.StatusConflict) {
					msg = "qWDTT server password limit reached: " + msg
				}
				_ = s.saveRow(inboundID, email, row, hasRow, "", 0, 0, msg)
				return nil, false, err
			}
			server, onServer = created, true
			owned[created.Password] = true
		}
		fresh = true
	}

	fields := url.Values{}
	if want.hashes != "" && tunnel.NormalizeVkHashes(server.VkHash) != want.hashes {
		fields.Set("vk_hash", want.hashes)
	}
	if server.MaxDevices != want.maxDevices {
		fields.Set("max_devices", strconv.Itoa(want.maxDevices))
	}
	if server.ExpiresAt > 0 && time.Until(time.Unix(server.ExpiresAt, 0)) < qwdttRenewBelowDays*24*time.Hour {
		fields.Set("days", strconv.Itoa(qwdttServerDays))
	}
	if server.Label != email {
		fields.Set("label", email)
	}
	var lastErr string
	var firstErr error
	if len(fields) > 0 {
		if err := api.Update(ctx, server.Password, fields); err != nil {
			lastErr, firstErr = err.Error(), err
		}
	}
	if server.IsDeactivated == want.active {
		if err := api.SetActive(ctx, server.Password, want.active); err != nil {
			lastErr, firstErr = err.Error(), err
		}
	}

	// Новая/подхваченная запись: запоминаем счётчики без начисления —
	// исторический трафик не должен сразу съесть лимит клиента.
	var delta *xray.ClientTraffic
	if !fresh && row.Password == server.Password {
		up, down := server.UpBytes-row.UpBytes, server.DownBytes-row.DownBytes
		if server.UpBytes < row.UpBytes {
			up = server.UpBytes
		}
		if server.DownBytes < row.DownBytes {
			down = server.DownBytes
		}
		if up > 0 || down > 0 {
			delta = &xray.ClientTraffic{Email: email, Up: up, Down: down}
		}
	}
	if err := s.saveRow(inboundID, email, row, hasRow, server.Password, server.UpBytes, server.DownBytes, lastErr); err != nil && firstErr == nil {
		firstErr = err
	}
	return delta, want.active && server.ActiveDevices > 0, firstErr
}

func (s *QwdttMemberService) saveRow(inboundID int, email string, row model.QwdttMember, hasRow bool, password string, up, down int64, lastErr string) error {
	if hasRow && row.Password == password && row.UpBytes == up && row.DownBytes == down && row.LastError == lastErr {
		return nil
	}
	if hasRow && password == "" && row.Password != "" {
		// Ошибка создания не должна затирать ранее выданный пароль.
		password, up, down = row.Password, row.UpBytes, row.DownBytes
	}
	next := model.QwdttMember{
		InboundId:   inboundID,
		ClientEmail: email,
		Password:    password,
		UpBytes:     up,
		DownBytes:   down,
		LastError:   lastErr,
	}
	if hasRow {
		return database.GetDB().Model(&model.QwdttMember{}).Where("id = ?", row.Id).
			Updates(map[string]any{"password": password, "up_bytes": up, "down_bytes": down, "last_error": lastErr}).Error
	}
	return database.GetDB().Create(&next).Error
}

// clientWantsActive: клиент включён, не истёк и не исчерпал трафик.
func clientWantsActive(client model.Client, now time.Time) bool {
	active := client.Enable && (client.ExpiryTime <= 0 || client.ExpiryTime > now.UnixMilli())
	if active && client.TotalGB > 0 {
		if traffic, err := (&InboundService{}).GetClientTrafficByEmail(client.Email); err == nil && traffic != nil {
			active = traffic.Up+traffic.Down < client.TotalGB
		}
	}
	return active
}

// TunnelMemberStatus — состояние индивидуального доступа клиента в одном
// VK TURN инбаунде (для формы клиента).
type TunnelMemberStatus struct {
	InboundId int    `json:"inboundId"`
	Remark    string `json:"remark"`
	Protocol  string `json:"protocol"`
	Ready     bool   `json:"ready"`
	Error     string `json:"error,omitempty"`
}

// ClientTunnelStatus собирает состояние qWDTT/CSQTT-доступов клиента.
func ClientTunnelStatus(email string) []TunnelMemberStatus {
	out := []TunnelMemberStatus{}
	var inbounds []*model.Inbound
	if err := database.GetDB().Where("protocol IN ?", []string{string(model.Qwdtt), string(model.Csqtt)}).Find(&inbounds).Error; err != nil {
		return out
	}
	for _, ib := range inbounds {
		attached, err := (&ClientService{}).ListForInbound(nil, ib.Id)
		if err != nil {
			continue
		}
		found := false
		for _, c := range attached {
			if c.Email == email {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		st := TunnelMemberStatus{InboundId: ib.Id, Remark: ib.Remark, Protocol: string(ib.Protocol)}
		switch ib.Protocol {
		case model.Qwdtt:
			cfg, _ := tunnel.QwdttConfigFromInbound(ib)
			if !cfg.PerClient {
				st.Error = "shared password mode (per-client passwords are off on this inbound)"
				break
			}
			if !cfg.QwdttPerClientActive() {
				st.Error = "qWDTT binary has no admin API (-admin-listen)"
				break
			}
			var row model.QwdttMember
			if database.GetDB().Where("inbound_id = ? AND client_email = ?", ib.Id, email).First(&row).Error == nil {
				st.Ready = row.Password != ""
				st.Error = row.LastError
			} else {
				st.Error = "pending sync"
			}
		case model.Csqtt:
			if _, ok := GetCsqttMemberService().Link(ib.Id, email); ok {
				st.Ready = true
			} else {
				st.Error = "pending sync"
			}
		}
		out = append(out, st)
	}
	return append(out, clientVkturnStatus(email)...)
}

// clientVkturnStatus — релеи VK TURN, через которые клиент получает
// vkturnproxy:// (он прикреплён к их WireGuard-инбаунду).
func clientVkturnStatus(email string) []TunnelMemberStatus {
	var relays []*model.Inbound
	if err := database.GetDB().Where("protocol = ?", model.Vkturn).Find(&relays).Error; err != nil {
		return nil
	}
	var out []TunnelMemberStatus
	for _, relay := range relays {
		cfg, ok := tunnel.VkturnConfigFromInbound(relay)
		if !ok || cfg.WgInboundId <= 0 {
			continue
		}
		attached, err := (&ClientService{}).ListForInbound(nil, cfg.WgInboundId)
		if err != nil {
			continue
		}
		for _, c := range attached {
			if c.Email != email {
				continue
			}
			st := TunnelMemberStatus{InboundId: relay.Id, Remark: relay.Remark, Protocol: string(model.Vkturn), Ready: true}
			switch {
			case !relay.Enable:
				st.Ready, st.Error = false, "relay inbound is disabled"
			case EffectiveVkHashes(email, cfg.VkHashes) == "":
				st.Ready, st.Error = false, "no VK hashes: set them on the client or the relay"
			case c.PrivateKey == "":
				st.Ready, st.Error = false, "client has no WireGuard private key"
			}
			out = append(out, st)
			break
		}
	}
	return out
}
