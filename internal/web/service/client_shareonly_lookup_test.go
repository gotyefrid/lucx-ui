// Copyright (c) 2026 LucX-UI Project.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// LucX-UI Component. Free for personal and educational use.
// Commercial use (including VPN resale) requires explicit written permission from the author.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package service

import (
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

var shareOnlyLookupProtocols = []model.Protocol{model.Qwdtt, model.Csqtt, model.Tproxy}

func createShareOnlyFox(t *testing.T, proto model.Protocol) {
	t.Helper()
	setupBulkDB(t)
	share := mkInbound(t, 57200, proto, `{"remark":"share"}`)
	if _, err := (&ClientService{}).Create(&InboundService{}, &ClientCreatePayload{
		Client:     model.Client{Email: "fox", SubID: "sub-fox", Enable: true},
		InboundIds: []int{share.Id},
	}); err != nil {
		t.Fatalf("Create on %s: %v", proto, err)
	}
}

// Reproduces the bot report: Links and QR on a qWDTT/CSQTT client answered
// "error in operation" because the lookup only read the inbound's settings.clients.
func TestGetClientByEmailOnShareOnlyInbound(t *testing.T) {
	for _, proto := range shareOnlyLookupProtocols {
		t.Run(string(proto), func(t *testing.T) {
			createShareOnlyFox(t, proto)
			traffic, client, err := (&InboundService{}).GetClientByEmail("fox")
			if err != nil {
				t.Fatalf("GetClientByEmail: %v", err)
			}
			if client == nil || client.Email != "fox" || client.SubID != "sub-fox" {
				t.Fatalf("client = %+v, want fox with sub-fox", client)
			}
			if traffic == nil || traffic.Email != "fox" {
				t.Fatalf("traffic = %+v, want the fox row", traffic)
			}
		})
	}
}

// Bulk enable/disable skipped every share-only client with "Client Not Found
// In Inbound" for the same reason.
func TestBulkSetEnableOnShareOnlyInbound(t *testing.T) {
	for _, proto := range shareOnlyLookupProtocols {
		t.Run(string(proto), func(t *testing.T) {
			createShareOnlyFox(t, proto)
			res, _, err := (&ClientService{}).BulkSetEnable(&InboundService{}, []string{"fox"}, false)
			if err != nil {
				t.Fatalf("BulkSetEnable: %v", err)
			}
			if res.Changed != 1 || len(res.Skipped) != 0 {
				t.Fatalf("changed=%d skipped=%+v, want 1 changed and none skipped", res.Changed, res.Skipped)
			}
			var rec model.ClientRecord
			if err := database.GetDB().Where("email = ?", "fox").First(&rec).Error; err != nil || rec.Enable {
				t.Fatalf("client record enable = %v (%v), want false", rec.Enable, err)
			}
			var tr xray.ClientTraffic
			if err := database.GetDB().Where("email = ?", "fox").First(&tr).Error; err != nil || tr.Enable {
				t.Fatalf("traffic enable = %v (%v), want false", tr.Enable, err)
			}
		})
	}
}
