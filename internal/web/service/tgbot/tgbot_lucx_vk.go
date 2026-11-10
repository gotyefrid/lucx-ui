// Copyright (c) 2026 LucX-UI Project.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// LucX-UI Component. Free for personal and educational use.
// Commercial use (including VPN resale) requires explicit written permission from the author.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package tgbot

import (
	"html"
	"slices"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"

	"github.com/mymmrac/telego"
	tu "github.com/mymmrac/telego/telegoutil"
)

// VK-хеши звонка клиента wdtt/CSQTT/iOS-релея: поле мастера и действие на карточке.
const (
	draftVkAwaiting        = "awaiting_vk_hashes"
	clientVkAwaitingPrefix = "awaiting_client_vk:"
)

func vkInputClears(input string) bool {
	input = strings.TrimSpace(input)
	return input == "" || input == "-" || strings.EqualFold(input, "none")
}

func setDraftVkHashes(draft *clientDraft, input string) error {
	if vkInputClears(input) {
		draft.vkHashes = ""
		return nil
	}
	hashes, err := service.NormalizeClientVkHashes(input)
	if err != nil {
		return err
	}
	draft.vkHashes = hashes
	return nil
}

func draftInboundIDs(draft *clientDraft) []int {
	if len(draft.receiverInboundIDs) == 0 && draft.receiverInboundID > 0 {
		return []int{draft.receiverInboundID}
	}
	return draft.receiverInboundIDs
}

func (t *Tgbot) vkDraftRows(draft *clientDraft) [][]telego.InlineKeyboardButton {
	if !service.InboundsTakeClientVk(draftInboundIDs(draft)) {
		return nil
	}
	return [][]telego.InlineKeyboardButton{tu.InlineKeyboardRow(
		tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.vkHashes")).WithCallbackData("add_client_ch_default_vk"),
	)}
}

func (t *Tgbot) vkDraftLine(draft *clientDraft) string {
	if draft.vkHashes == "" && !service.InboundsTakeClientVk(draftInboundIDs(draft)) {
		return ""
	}
	value := draft.vkHashes
	if value == "" {
		value = "—"
	}
	return "📞 VK: <code>" + html.EscapeString(value) + "</code>\r\n"
}

func vkPromptValue(hashes string) string {
	if hashes == "" {
		return "—"
	}
	return hashes
}

func (t *Tgbot) promptDraftVk(chatID int64, actor chatUser, draft *clientDraft) {
	userStateMgr.set(actor, draftVkAwaiting)
	t.wizardPrompt(chatID, draft, t.I18nBot("tgbot.messages.vkHashes_prompt",
		"ClientVk=="+html.EscapeString(vkPromptValue(draft.vkHashes))))
}

// handleDraftVkInput keeps the state on a rejected value so the admin can retry.
func (t *Tgbot) handleDraftVkInput(message *telego.Message, actor chatUser, draft *clientDraft) {
	t.deleteIncoming(message)
	if err := setDraftVkHashes(draft, message.Text); err != nil {
		rows := append([][]telego.InlineKeyboardButton{}, t.getCommonClientButtons(draft)...)
		rows = append(rows, tu.InlineKeyboardRow(t.btn("tgbot.buttons.use_default", "add_client_default_info")))
		t.renderScreen(message.Chat.ID, t.newScreen("wizard",
			t.BuildClientDraftMessage(draft)+"\n\n"+t.I18nBot("tgbot.messages.vkHashes_invalid",
				"Error=="+html.EscapeString(err.Error())), rows...))
		return
	}
	userStateMgr.clear(actor)
	t.addClient(message.Chat.ID, draft, t.BuildClientDraftMessage(draft))
}

// applyDraftVkHashes runs after Create: the member sync sweeps hashes of emails
// that have no client yet, so storing them earlier would lose them.
func applyDraftVkHashes(draft *clientDraft) {
	if draft.vkHashes == "" {
		return
	}
	if err := service.SetClientVkHashes(draft.email, draft.vkHashes); err != nil {
		logger.Warningf("tgbot: VK hashes of %q not saved: %v", draft.email, err)
		return
	}
	service.TriggerCsqttMemberSync()
}

func insertKeyboardRows(rows [][]telego.InlineKeyboardButton, at int, extra [][]telego.InlineKeyboardButton) [][]telego.InlineKeyboardButton {
	return slices.Insert(rows, at, extra...)
}

func (t *Tgbot) clientVkRows(email string) [][]telego.InlineKeyboardButton {
	if len(service.ClientTunnelStatus(email)) == 0 {
		return nil
	}
	return [][]telego.InlineKeyboardButton{tu.InlineKeyboardRow(
		t.btn("tgbot.buttons.vkHashes", t.encodeQuery("client_vk "+email)),
	)}
}

func (t *Tgbot) promptClientVk(chatID int64, actor chatUser, email string) {
	userStateMgr.set(actor, clientVkAwaitingPrefix+email)
	body := t.I18nBot("tgbot.messages.vkHashes_prompt",
		"ClientVk=="+html.EscapeString(vkPromptValue(service.ClientVkHashes(email))))
	t.renderScreen(chatID, t.newScreen("client", body,
		tu.InlineKeyboardRow(t.btn("tgbot.buttons.cancel", t.encodeQuery("client_cancel "+email)))))
}

func (t *Tgbot) saveClientVkHashes(email, input string) error {
	if vkInputClears(input) {
		input = ""
	}
	if err := service.SetClientVkHashes(email, input); err != nil {
		return err
	}
	service.TriggerCsqttMemberSync()
	return nil
}

// handleClientVkInput reports whether the message answered a card's VK prompt.
func (t *Tgbot) handleClientVkInput(message *telego.Message, actor chatUser, state string) bool {
	email, ok := strings.CutPrefix(state, clientVkAwaitingPrefix)
	if !ok {
		return false
	}
	t.deleteIncoming(message)
	if err := t.saveClientVkHashes(email, message.Text); err != nil {
		t.sendNotice(message.Chat.ID, t.I18nBot("tgbot.messages.vkHashes_invalid",
			"Error=="+html.EscapeString(err.Error())))
		return true
	}
	userStateMgr.clear(actor)
	t.searchClientScreen(message.Chat.ID, email)
	return true
}
