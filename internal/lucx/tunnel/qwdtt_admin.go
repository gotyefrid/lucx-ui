// Copyright (c) 2026 LucX-UI Project.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// LucX-UI Component. Free for personal and educational use.
// Commercial use (including VPN resale) requires explicit written permission from the author.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// QwdttAdminDefaultPort — порт admin API qWDTT на 127.0.0.1 по умолчанию.
const QwdttAdminDefaultPort = 56010

// Имена файлов admin API в каталоге состояния qWDTT (рядом с passwords.json).
const (
	qwdttAdminTokenFile = "panel-admin-token"
	qwdttAdminCertFile  = "panel-admin-cert.pem"
	qwdttAdminKeyFile   = "panel-admin-key.pem"
)

// EffectiveAdminPort возвращает порт admin API с учётом значения по умолчанию.
func (c QwdttConfig) EffectiveAdminPort() int {
	if c.AdminPort > 0 {
		return c.AdminPort
	}
	return QwdttAdminDefaultPort
}

// AdminAddr — адрес admin API (всегда loopback).
func (c QwdttConfig) AdminAddr() string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(c.EffectiveAdminPort()))
}

var (
	qwdttAdminProbeOnce sync.Once
	qwdttAdminProbeOK   bool
)

// QwdttSupportsAdminAPI: бинарь qWDTT знает флаги -admin-listen/-admin-token-file
// (SpaceNeuroX ≥ 1.4.4). Без них perClient не включаем, иначе процесс упадёт
// на неизвестном флаге и общий пароль тоже перестанет работать.
func QwdttSupportsAdminAPI() bool {
	qwdttAdminProbeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		b, _ := exec.CommandContext(ctx, Qwdtt.BinaryPath(), "-h").CombinedOutput()
		out := string(b)
		qwdttAdminProbeOK = strings.Contains(out, "admin-listen") && strings.Contains(out, "admin-token-file")
	})
	return qwdttAdminProbeOK
}

// SetQwdttAdminSupportForTest подменяет результат пробы бинаря. Только для тестов.
func SetQwdttAdminSupportForTest(ok bool) (restore func()) {
	qwdttAdminProbeOnce.Do(func() {})
	prev := qwdttAdminProbeOK
	qwdttAdminProbeOK = ok
	return func() { qwdttAdminProbeOK = prev }
}

// QwdttPerClientActive: инбаунд просит perClient и бинарь это умеет.
func (c QwdttConfig) QwdttPerClientActive() bool {
	return c.PerClient && QwdttSupportsAdminAPI()
}

// QwdttAdminFiles — пути к токену и TLS-паре admin API.
type QwdttAdminFiles struct {
	Token string
	Cert  string
	Key   string
}

// QwdttAdminPaths возвращает пути файлов admin API в каталоге dir.
func QwdttAdminPaths(dir string) QwdttAdminFiles {
	return QwdttAdminFiles{
		Token: filepath.Join(dir, qwdttAdminTokenFile),
		Cert:  filepath.Join(dir, qwdttAdminCertFile),
		Key:   filepath.Join(dir, qwdttAdminKeyFile),
	}
}

// EnsureQwdttAdminFiles создаёт (если их нет) токен и самоподписанный
// сертификат admin API. Существующие файлы не трогает: токен стабилен между
// перезапусками, иначе процесс пришлось бы перезапускать на каждом тике.
func EnsureQwdttAdminFiles(dir string) (QwdttAdminFiles, error) {
	files := QwdttAdminPaths(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return files, err
	}
	if !fileNonEmpty(files.Token) {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return files, err
		}
		if err := writeFileAtomic(files.Token, []byte(hex.EncodeToString(buf)+"\n"), 0o600); err != nil {
			return files, err
		}
	}
	if !fileNonEmpty(files.Cert) || !fileNonEmpty(files.Key) {
		certPEM, keyPEM, err := selfSignedLoopbackCert()
		if err != nil {
			return files, err
		}
		if err := writeFileAtomic(files.Key, keyPEM, 0o600); err != nil {
			return files, err
		}
		if err := writeFileAtomic(files.Cert, certPEM, 0o600); err != nil {
			return files, err
		}
	}
	return files, nil
}

// AdminArgs — флаги admin API для argv qWDTT.
func (f QwdttAdminFiles) AdminArgs(addr string) []string {
	return []string{
		"-admin-listen", addr,
		"-admin-token-file", f.Token,
		"-admin-cert", f.Cert,
		"-admin-key", f.Key,
	}
}

func fileNonEmpty(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular() && st.Size() > 0
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func selfSignedLoopbackCert() ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "qwdtt-admin"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(20, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// ---- клиент admin API ----

// QwdttAdminPassword — пароль в ответе GET /admin/passwords.
type QwdttAdminPassword struct {
	Password      string   `json:"password"`
	Label         string   `json:"label"`
	VkHash        string   `json:"vk_hash"`
	MaxDevices    int      `json:"max_devices"`
	DeviceIDs     []string `json:"device_ids"`
	ExpiresAt     int64    `json:"expires_at"`
	IsDeactivated bool     `json:"is_deactivated"`
	DownBytes     int64    `json:"down_bytes"`
	UpBytes       int64    `json:"up_bytes"`
	ActiveDevices int      `json:"active_devices"`
}

// QwdttAdminError — ответ admin API с кодом ошибки (409 = лимит паролей и т.п.).
type QwdttAdminError struct {
	Status  int
	Message string
}

func (e *QwdttAdminError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("qWDTT admin API HTTP %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("qWDTT admin API HTTP %d", e.Status)
}

// IsQwdttAdminStatus сообщает, что err — ответ admin API с данным HTTP-кодом.
func IsQwdttAdminStatus(err error, status int) bool {
	var apiErr *QwdttAdminError
	return errors.As(err, &apiErr) && apiErr.Status == status
}

// QwdttAdminClient ходит в admin API локального qWDTT.
type QwdttAdminClient struct {
	base   string
	token  string
	client *http.Client
}

// NewQwdttAdminClient читает токен из каталога состояния и готовит клиента.
// Сертификат самоподписанный и лежит рядом — проверяем по нему (pinning).
func NewQwdttAdminClient(cfg QwdttConfig) (*QwdttAdminClient, error) {
	return newQwdttAdminClientIn(cfg, cfg.ResolveConfigDir())
}

func newQwdttAdminClientIn(cfg QwdttConfig, dir string) (*QwdttAdminClient, error) {
	files := QwdttAdminPaths(dir)
	tokenRaw, err := os.ReadFile(files.Token)
	if err != nil {
		return nil, fmt.Errorf("qWDTT admin token: %w", err)
	}
	token := strings.TrimSpace(string(tokenRaw))
	if token == "" {
		return nil, errors.New("qWDTT admin token is empty")
	}
	certPEM, err := os.ReadFile(files.Cert)
	if err != nil {
		return nil, fmt.Errorf("qWDTT admin cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		return nil, errors.New("qWDTT admin cert is not valid PEM")
	}
	return &QwdttAdminClient{
		base:  "https://" + cfg.AdminAddr(),
		token: token,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12},
				Proxy:           nil,
			},
		},
	}, nil
}

func (a *QwdttAdminClient) do(ctx context.Context, method, path string, form url.Values, out any) error {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		return &QwdttAdminError{Status: resp.StatusCode, Message: e.Error}
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// List возвращает все пароли сервера (кроме главного).
func (a *QwdttAdminClient) List(ctx context.Context) ([]QwdttAdminPassword, error) {
	var out struct {
		Passwords []QwdttAdminPassword `json:"passwords"`
	}
	if err := a.do(ctx, http.MethodGet, "/admin/passwords", nil, &out); err != nil {
		return nil, err
	}
	return out.Passwords, nil
}

// Create заводит новый пароль; сервер сам генерирует его и WRAP-ключ.
func (a *QwdttAdminClient) Create(ctx context.Context, label, vkHash string, maxDevices, days int) (QwdttAdminPassword, error) {
	form := url.Values{}
	form.Set("label", label)
	form.Set("vk_hash", vkHash)
	form.Set("max_devices", strconv.Itoa(maxDevices))
	form.Set("days", strconv.Itoa(days))
	var out QwdttAdminPassword
	err := a.do(ctx, http.MethodPost, "/admin/passwords", form, &out)
	return out, err
}

// Update меняет только переданные поля (label, vk_hash, max_devices, days).
func (a *QwdttAdminClient) Update(ctx context.Context, password string, fields url.Values) error {
	form := url.Values{}
	for k, v := range fields {
		form[k] = v
	}
	form.Set("password", password)
	return a.do(ctx, http.MethodPost, "/admin/passwords/update", form, nil)
}

// SetActive включает или выключает пароль (выключение рвёт сессии устройств).
func (a *QwdttAdminClient) SetActive(ctx context.Context, password string, active bool) error {
	path := "/admin/passwords/deactivate"
	if active {
		path = "/admin/passwords/activate"
	}
	return a.do(ctx, http.MethodPost, path, url.Values{"password": {password}}, nil)
}

// Delete удаляет пароль вместе с привязанными устройствами.
func (a *QwdttAdminClient) Delete(ctx context.Context, password string) error {
	return a.do(ctx, http.MethodPost, "/admin/passwords/delete", url.Values{"password": {password}}, nil)
}
