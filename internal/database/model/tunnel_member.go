// Copyright (c) 2026 LucX-UI Project.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// LucX-UI Component. Free for personal and educational use.
// Commercial use (including VPN resale) requires explicit written permission from the author.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package model

// QwdttMember — пароль на сервере qWDTT, заведённый панелью для одного
// клиента (режим perClient). Пароли, созданные вручную (бот, admin API),
// сюда не попадают, пока панель не подхватит их по label == email клиента.
type QwdttMember struct {
	Id          int    `json:"id" gorm:"primaryKey;autoIncrement"`
	InboundId   int    `json:"inboundId" gorm:"uniqueIndex:idx_qwdtt_member_client"`
	ClientEmail string `json:"clientEmail" gorm:"uniqueIndex:idx_qwdtt_member_client"`
	// Password пуст, пока сервер не создал пароль (см. LastError).
	Password string `json:"-"`
	// UpBytes/DownBytes — последние прочитанные счётчики сервера; панель
	// начисляет клиенту только прирост.
	UpBytes   int64  `json:"-" gorm:"default:0"`
	DownBytes int64  `json:"-" gorm:"default:0"`
	LastError string `json:"lastError" gorm:"type:text;default:''"`
	CreatedAt int64  `json:"createdAt" gorm:"autoCreateTime:milli"`
	UpdatedAt int64  `json:"updatedAt" gorm:"autoUpdateTime:milli"`
}

// TunnelClientVk — индивидуальные VK-хеши клиента для VK TURN туннелей
// (qWDTT, CSQTT). Пустое значение = берутся хеши из настроек инбаунда.
type TunnelClientVk struct {
	ClientEmail string `json:"clientEmail" gorm:"primaryKey"`
	VkHashes    string `json:"vkHashes" gorm:"type:text;default:''"`
	UpdatedAt   int64  `json:"updatedAt" gorm:"autoUpdateTime:milli"`
}
