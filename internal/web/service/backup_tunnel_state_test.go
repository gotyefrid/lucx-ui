// Copyright (c) 2026 LucX-UI Project.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// LucX-UI Component. Free for personal and educational use.
// Commercial use (including VPN resale) requires explicit written permission from the author.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package service

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/lucx/tunnel"

	_ "github.com/mattn/go-sqlite3"
)

func writeStateFile(t *testing.T, rel, content string) {
	t.Helper()
	p := filepath.Join(tunnel.WorkDir(), filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readStateFile(t *testing.T, rel string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(tunnel.WorkDir(), filepath.FromSlash(rel)))
	if os.IsNotExist(err) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b), true
}

// liveWALDatabase leaves a committed row only in the -wal file, the way a
// running CSQTT keeps its database: a raw copy of the main file misses it.
func liveWALDatabase(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, q := range []string{
		"PRAGMA wal_autocheckpoint=0",
		"CREATE TABLE passwords (password TEXT PRIMARY KEY, name TEXT)",
		"INSERT INTO passwords VALUES ('p1', 'Инна')",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	return db
}

// Sidecar state (qWDTT passwords, CSQTT members, server keys) lives only on
// disk; a backup moved to a new server must bring it back or every issued
// client config stops working.
func TestBackupTunnelStateRoundTrip(t *testing.T) {
	initBackupSiteTestDB(t)
	writeStateFile(t, "qwdtt-data/passwords.json", `{"passwords":{"p":{"label":"router"}}}`)
	writeStateFile(t, "qwdtt-data/wg-keys.dat", "server-keys")
	writeStateFile(t, "qwdtt-data/server.log", "noise")
	writeStateFile(t, "qwdtt-data/.passwords-1.tmp", "half-written")
	writeStateFile(t, "naive-12-data/caddy/certificates/a.crt", "cert")
	writeStateFile(t, "csqtt.conf", "rendered from the database")
	csqttDB := filepath.Join(tunnel.WorkDir(), "csqtt-data", "csqtt.db")
	if err := os.MkdirAll(filepath.Dir(csqttDB), 0o700); err != nil {
		t.Fatal(err)
	}
	liveWALDatabase(t, csqttDB)

	backupPath := filepath.Join(t.TempDir(), "backup.db")
	if err := database.BackupSQLite(backupPath); err != nil {
		t.Fatal(err)
	}
	if err := embedBackupTunnelState(backupPath); err != nil {
		t.Fatalf("embed: %v", err)
	}

	// The new server: empty state dirs, the backup imported as the live DB.
	if err := os.RemoveAll(tunnel.WorkDir()); err != nil {
		t.Fatal(err)
	}
	writeStateFile(t, "qwdtt-data/passwords.json", `{"passwords":{}}`)
	if err := database.CloseDB(); err != nil {
		t.Fatal(err)
	}
	if err := database.InitDB(backupPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.CloseDB() })

	if err := restoreBackupTunnelState(); err != nil {
		t.Fatalf("restore: %v", err)
	}

	for rel, want := range map[string]string{
		"qwdtt-data/passwords.json":              `{"passwords":{"p":{"label":"router"}}}`,
		"qwdtt-data/wg-keys.dat":                 "server-keys",
		"naive-12-data/caddy/certificates/a.crt": "cert",
	} {
		if got, ok := readStateFile(t, rel); !ok || got != want {
			t.Fatalf("%s restored as %q (present=%v), want %q", rel, got, ok, want)
		}
	}
	for _, rel := range []string{"qwdtt-data/server.log", "qwdtt-data/.passwords-1.tmp", "csqtt.conf"} {
		if _, ok := readStateFile(t, rel); ok {
			t.Fatalf("%s must not travel with the backup", rel)
		}
	}
	restored, err := sql.Open("sqlite3", filepath.Join(tunnel.WorkDir(), "csqtt-data", "csqtt.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var name string
	if err := restored.QueryRow("SELECT name FROM passwords WHERE password = 'p1'").Scan(&name); err != nil || name != "Инна" {
		t.Fatalf("CSQTT member lost in the backup: %q, %v", name, err)
	}
	if info, err := os.Stat(filepath.Join(tunnel.WorkDir(), "qwdtt-data", "wg-keys.dat")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("restored secret mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
	if database.GetDB().Migrator().HasTable(backupTunnelStateTable) {
		t.Fatal("state table left in the live database")
	}
}

func TestRestoreBackupTunnelStateRejectsEscapes(t *testing.T) {
	for name, row := range map[string]backupTunnelFile{
		"path traversal": {Dir: "qwdtt-data", Path: "../escape", Data: []byte("evil")},
		"foreign dir":    {Dir: "../etc", Path: "passwd", Data: []byte("evil")},
		"not a data dir": {Dir: "cover-1-site", Path: "index.html", Data: []byte("evil")},
	} {
		t.Run(name, func(t *testing.T) {
			initBackupSiteTestDB(t)
			g := database.GetDB()
			if err := g.AutoMigrate(&backupTunnelFile{}); err != nil {
				t.Fatal(err)
			}
			if err := g.Create(&row).Error; err != nil {
				t.Fatal(err)
			}
			if err := restoreBackupTunnelState(); err == nil {
				t.Fatal("unsafe row accepted")
			}
			entries, _ := os.ReadDir(filepath.Dir(tunnel.WorkDir()))
			for _, e := range entries {
				if e.Name() == "escape" || e.Name() == "etc" {
					t.Fatalf("wrote %s outside the tunnel dir", e.Name())
				}
			}
			if _, ok := readStateFile(t, "cover-1-site/index.html"); ok {
				t.Fatal("restored a non-state dir")
			}
			var count int64
			g.Table(backupTunnelStateTable).Count(&count)
			if count != 1 {
				t.Fatalf("rows dropped after a failed restore: %d left", count)
			}
		})
	}
}

// A backup from a panel without this feature must leave sidecar state alone.
func TestRestoreBackupTunnelStateWithoutTableKeepsState(t *testing.T) {
	initBackupSiteTestDB(t)
	writeStateFile(t, "qwdtt-data/passwords.json", "current")
	if err := restoreBackupTunnelState(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, ok := readStateFile(t, "qwdtt-data/passwords.json"); !ok || got != "current" {
		t.Fatalf("state changed by a backup without state: %q (present=%v)", got, ok)
	}
}
