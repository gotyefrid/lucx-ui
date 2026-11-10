// Copyright (c) 2026 LucX-UI Project.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// LucX-UI Component. Free for personal and educational use.
// Commercial use (including VPN resale) requires explicit written permission from the author.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package tunnel

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestNormalizeVkHashes(t *testing.T) {
	cases := map[string]string{
		"":                      "",
		" a , b ,, a ":          "a,b",
		"a\nb;c d":              "a,b,c,d",
		"abc-DEF_1,abc-DEF_1,x": "abc-DEF_1,x",
		"https://vk.com/call/join/AbC_1?x=1\nhttps://vk.ru/call/join/Zz-2": "AbC_1,Zz-2",
	}
	for in, want := range cases {
		if got := NormalizeVkHashes(in); got != want {
			t.Errorf("NormalizeVkHashes(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestQwdttMemberURIs(t *testing.T) {
	cfg := DefaultQwdttConfig()
	cfg.Remark = "srv"
	cfg.SubHost = "1.2.3.4:56000"
	cfg.Password = "MAINPASS"
	cfg.VkHashes = "shared"

	member := cfg.MemberURI("CLIENTPASS", " h1, h2 ")
	u, err := url.Parse(member)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("pass") != "CLIENTPASS" || q.Get("hashes") != "h1,h2" || q.Get("peer") != "1.2.3.4:56000" {
		t.Fatalf("unexpected member URI %q", member)
	}
	if strings.Contains(member, "MAINPASS") {
		t.Fatal("member URI leaks the main password")
	}
	// Общая ссылка не изменилась: главный пароль и хеши инбаунда как есть.
	if shared := cfg.ClientURI(); !strings.Contains(shared, "pass=MAINPASS") || !strings.Contains(shared, "hashes=shared") {
		t.Fatalf("shared URI changed: %q", shared)
	}

	legacy := cfg.MemberLegacyURI("CLIENTPASS", "h1, h2")
	if want := "wdtt://1.2.3.4:56000:56001:9000:CLIENTPASS:h1,h2"; legacy != want {
		t.Fatalf("legacy = %q, want %q", legacy, want)
	}
	if cfg.MemberLegacyURI("CLIENTPASS", "") != "" {
		t.Fatal("legacy URI without hashes must be empty")
	}
}

func TestQwdttValidateAdminPort(t *testing.T) {
	cfg := DefaultQwdttConfig()
	cfg.PerClient = true
	cfg.AdminPort = cfg.WGPort
	if cfg.Validate() == nil {
		t.Fatal("adminPort equal to wgPort must be rejected")
	}
	cfg.AdminPort = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default admin port: %v", err)
	}
	if cfg.AdminAddr() != "127.0.0.1:56010" {
		t.Fatalf("AdminAddr = %q", cfg.AdminAddr())
	}
}

func TestEnsureQwdttAdminFilesStable(t *testing.T) {
	dir := t.TempDir()
	files, err := EnsureQwdttAdminFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	token1, _ := os.ReadFile(files.Token)
	cert1, _ := os.ReadFile(files.Cert)
	if len(strings.TrimSpace(string(token1))) != 64 {
		t.Fatalf("token %q", token1)
	}
	if st, _ := os.Stat(files.Key); st.Mode().Perm() != 0o600 {
		t.Fatalf("key perm %v", st.Mode().Perm())
	}
	if _, err := tls.LoadX509KeyPair(files.Cert, files.Key); err != nil {
		t.Fatalf("cert/key pair: %v", err)
	}
	if _, err := EnsureQwdttAdminFiles(dir); err != nil {
		t.Fatal(err)
	}
	token2, _ := os.ReadFile(files.Token)
	cert2, _ := os.ReadFile(files.Cert)
	if string(token1) != string(token2) || string(cert1) != string(cert2) {
		t.Fatal("admin files must not be regenerated when present")
	}
}

func TestQwdttInstanceAdminArgs(t *testing.T) {
	t.Setenv("XUI_BIN_FOLDER", t.TempDir())
	ib := &model.Inbound{Id: 7, Protocol: model.Qwdtt, Enable: true, Port: 56000,
		Settings: `{"password":"p","perClient":true,"routeThroughXray":false}`}

	restore := SetQwdttAdminSupportForTest(false)
	inst, ok := QwdttInstanceFromInbound(ib)
	restore()
	if !ok || strings.Contains(strings.Join(inst.Args, " "), "-admin-listen") {
		t.Fatalf("binary without admin API must not get admin flags: %v", inst.Args)
	}

	restore = SetQwdttAdminSupportForTest(true)
	defer restore()
	inst, ok = QwdttInstanceFromInbound(ib)
	args := strings.Join(inst.Args, " ")
	if !ok || !strings.Contains(args, "-admin-listen 127.0.0.1:56010") || !strings.Contains(args, "-admin-token-file") {
		t.Fatalf("admin flags missing: %v", inst.Args)
	}

	ib.Settings = `{"password":"p","routeThroughXray":false}`
	inst, _ = QwdttInstanceFromInbound(ib)
	if strings.Contains(strings.Join(inst.Args, " "), "-admin-listen") {
		t.Fatal("shared mode must keep the old argv")
	}
}

func TestQwdttAdminClientPinnedTLS(t *testing.T) {
	dir := t.TempDir()
	files, err := EnsureQwdttAdminFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(files.Cert, files.Key)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := os.ReadFile(files.Token)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.TrimSpace(string(token)) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/admin/passwords":
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"password limit reached (max 10)"}`))
				return
			}
			_, _ = w.Write([]byte(`{"passwords":[{"password":"P1","label":"a@b","up_bytes":5}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)

	cfg := DefaultQwdttConfig()
	cfg.ConfigDir = dir
	cfg.AdminPort = p
	api, err := newQwdttAdminClientIn(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	list, err := api.List(context.Background())
	if err != nil || len(list) != 1 || list[0].Label != "a@b" || list[0].UpBytes != 5 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	_, err = api.Create(context.Background(), "x", "h", 1, 365)
	if !IsQwdttAdminStatus(err, http.StatusConflict) || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("create error = %v", err)
	}
}
