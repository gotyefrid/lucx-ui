package service

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/dbtest"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/web/runtime"
)

func qwdttSubnetTestInbound(settings string) *model.Inbound {
	return &model.Inbound{
		UserId:         1,
		Port:           56000,
		Protocol:       model.Qwdtt,
		Remark:         "qwdtt",
		Enable:         true,
		Settings:       settings,
		StreamSettings: `{}`,
		Sniffing:       `{}`,
	}
}

func initQwdttSubnetTest(t *testing.T) {
	t.Helper()
	dbtest.InitDB(t, filepath.Join(t.TempDir(), "x-ui.db"))
	prev := runtime.GetManager()
	runtime.SetManager(nil)
	t.Cleanup(func() { runtime.SetManager(prev) })
}

// Before validation ran on save, a bad subnet was stored and the sidecar was
// silently left disabled by QwdttInstanceFromInbound.
func TestAddInbound_QwdttRejectsBadSubnet(t *testing.T) {
	initQwdttSubnetTest(t)
	svc := &InboundService{}
	_, _, err := svc.AddInbound(qwdttSubnetTestInbound(`{"subHost":"1.2.3.4:56000","wgSubnet":"10.70.0.0/24"}`))
	if err == nil || !strings.Contains(err.Error(), "wgSubnet 10.70.0.0/24 overlaps rawSubnet 10.70.0.0/16") {
		t.Fatalf("AddInbound err = %v, want overlap rejection", err)
	}
}

func TestUpdateInbound_QwdttRejectsBadSubnet(t *testing.T) {
	initQwdttSubnetTest(t)
	svc := &InboundService{}
	ib, _, err := svc.AddInbound(qwdttSubnetTestInbound(`{"subHost":"1.2.3.4:56000"}`))
	if err != nil {
		t.Fatalf("AddInbound: %v", err)
	}
	var stored map[string]any
	if err := json.Unmarshal([]byte(ib.Settings), &stored); err != nil {
		t.Fatal(err)
	}
	if stored["wgSubnet"] != "10.68.0.0/16" || stored["rawSubnet"] != "10.70.0.0/16" {
		t.Fatalf("defaults not persisted: %s", ib.Settings)
	}

	upd := *ib
	upd.Settings = `{"subHost":"1.2.3.4:56000","password":"p","rawSubnet":"8.8.0.0/16"}`
	if _, _, err := svc.UpdateInbound(&upd); err == nil || !strings.Contains(err.Error(), "rawSubnet must be a private range") {
		t.Fatalf("UpdateInbound err = %v, want private-range rejection", err)
	}
}
