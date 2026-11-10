// Copyright (c) 2026 LucX-UI Project.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// LucX-UI Component. Free for personal and educational use.
// Commercial use (including VPN resale) requires explicit written permission from the author.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package service

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/lucx/tunnel"
)

// Sidecar state the panel DB lacks (qWDTT passwords, CSQTT members, server keys)
// rides in the backup copy like the masking sites do (backup_site_files.go).
const backupTunnelStateTable = "lucx_backup_tunnel_state"

const (
	backupTunnelFileMax     = 20 << 20
	backupTunnelStateMaxSum = 64 << 20
	tunnelStateDirSuffix    = "-data"
)

var sqliteMagic = []byte("SQLite format 3\x00")

// tunnelStateMu keeps the reconcile loop from starting a sidecar while its
// state dir is being replaced: the sidecar would load the old files and later
// save its memory over the restored ones.
var tunnelStateMu sync.Mutex

type backupTunnelFile struct {
	Dir  string `gorm:"column:dir;primaryKey"`
	Path string `gorm:"column:path;primaryKey"`
	Data []byte `gorm:"column:data"`
}

func (backupTunnelFile) TableName() string { return backupTunnelStateTable }

// skipTunnelStateFile leaves out what a sidecar recreates on its own or what
// is only a moment of a write in progress.
func skipTunnelStateFile(name string) bool {
	return strings.HasSuffix(name, ".log") ||
		strings.HasSuffix(name, ".tmp") ||
		strings.HasSuffix(name, ".lock") ||
		strings.HasSuffix(name, "-wal") ||
		strings.HasSuffix(name, "-shm") ||
		strings.HasSuffix(name, "-journal")
}

func embedBackupTunnelState(backupPath string) error {
	rows, err := collectTunnelStateRows()
	if err != nil {
		return err
	}
	g, err := openSQLiteCopy(backupPath)
	if err != nil {
		return err
	}
	defer func() {
		if sqlDB, dbErr := g.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
	}()
	if err := g.Migrator().DropTable(backupTunnelStateTable); err != nil {
		logger.Debugf("backup: tunnel state table not present: %v", err)
	}
	if len(rows) == 0 {
		return nil
	}
	if err := g.AutoMigrate(&backupTunnelFile{}); err != nil {
		return err
	}
	return g.CreateInBatches(rows, 50).Error
}

func collectTunnelStateRows() ([]backupTunnelFile, error) {
	root := tunnel.WorkDir()
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rows := []backupTunnelFile{}
	total := 0
	for _, e := range entries {
		if !e.IsDir() || !strings.HasSuffix(e.Name(), tunnelStateDirSuffix) {
			continue
		}
		dir := filepath.Join(root, e.Name())
		walkErr := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.Type().IsRegular() || skipTunnelStateFile(d.Name()) {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if info.Size() > backupTunnelFileMax {
				return fmt.Errorf("tunnel state file %s exceeds backup limit", p)
			}
			data, err := readTunnelStateFile(p)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			total += len(data)
			rows = append(rows, backupTunnelFile{Dir: e.Name(), Path: filepath.ToSlash(rel), Data: data})
			return nil
		})
		if walkErr != nil {
			return nil, walkErr
		}
	}
	if total > backupTunnelStateMaxSum {
		return nil, fmt.Errorf("tunnel state total %d bytes, backup ceiling is %d", total, backupTunnelStateMaxSum)
	}
	return rows, nil
}

// readTunnelStateFile snapshots a live SQLite database through SQLite itself:
// a running sidecar keeps fresh commits in the -wal file, a raw copy loses them.
func readTunnelStateFile(p string) ([]byte, error) {
	data, err := os.ReadFile(p)
	if err != nil || !bytes.HasPrefix(data, sqliteMagic) {
		return data, err
	}
	snapDir, err := os.MkdirTemp("", "lucx-state-snap-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(snapDir)
	snap := filepath.Join(snapDir, "snap.db")
	src, err := sql.Open("sqlite3", "file:"+p+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer src.Close()
	if _, err := src.Exec("VACUUM INTO ?", snap); err != nil {
		return nil, fmt.Errorf("snapshot %s: %w", p, err)
	}
	return os.ReadFile(snap)
}

var errBackupTunnelPath = errors.New("tunnel state path escapes its directory")

func validateTunnelStateDir(dir string) error {
	if !strings.HasSuffix(dir, tunnelStateDirSuffix) || dir == tunnelStateDirSuffix ||
		strings.ContainsAny(dir, `/\`) || strings.Contains(dir, "..") {
		return fmt.Errorf("%w: dir %q", errBackupTunnelPath, dir)
	}
	return nil
}

// restoreBackupTunnelState writes the embedded state dirs back after an import;
// the caller revives the stopped sidecars with Reconcile.
func restoreBackupTunnelState() error {
	db := database.GetDB()
	if db == nil || !db.Migrator().HasTable(backupTunnelStateTable) {
		return nil
	}
	var rows []backupTunnelFile
	if err := db.Find(&rows).Error; err != nil {
		return err
	}
	byDir := map[string][]backupTunnelFile{}
	for _, r := range rows {
		if err := validateTunnelStateDir(r.Dir); err != nil {
			return err
		}
		if err := validateBackupSitePath(filepath.ToSlash(r.Path)); err != nil {
			return fmt.Errorf("%w: %v", errBackupTunnelPath, err)
		}
		byDir[r.Dir] = append(byDir[r.Dir], r)
	}
	if len(byDir) > 0 {
		if err := replaceTunnelStateDirs(byDir); err != nil {
			return err
		}
	}
	if err := db.Migrator().DropTable(backupTunnelStateTable); err != nil {
		logger.Warningf("Import: drop %s: %v", backupTunnelStateTable, err)
	}
	return nil
}

func replaceTunnelStateDirs(byDir map[string][]backupTunnelFile) error {
	tunnelStateMu.Lock()
	defer tunnelStateMu.Unlock()
	tunnel.GetManager().StopAll()
	root := tunnel.WorkDir()
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	for dir, group := range byDir {
		stage, err := os.MkdirTemp(root, ".state-restore-")
		if err != nil {
			return err
		}
		for _, f := range group {
			out := filepath.Join(stage, filepath.FromSlash(f.Path))
			if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
				_ = os.RemoveAll(stage)
				return err
			}
			if err := os.WriteFile(out, f.Data, 0o600); err != nil {
				_ = os.RemoveAll(stage)
				return err
			}
		}
		if err := os.Chmod(stage, 0o700); err != nil {
			_ = os.RemoveAll(stage)
			return err
		}
		if err := tunnel.ReplaceSiteDir(filepath.Join(root, dir), stage); err != nil {
			_ = os.RemoveAll(stage)
			return err
		}
		logger.Infof("backup: restored %d tunnel state file(s) into %s", len(group), dir)
	}
	return nil
}
