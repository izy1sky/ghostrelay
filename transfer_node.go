package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Node side of file transfer. Every path goes through the same jail as the fs
// tools. Uploads land in a temp file next to the target and are renamed into
// place only after the size and sha256 check out.

const (
	maxChunk       = 4 << 20
	maxWalkEntries = 20000
	uploadIdle     = 10 * time.Minute
)

type upload struct {
	mu        sync.Mutex // one chunk at a time; guards written and touched
	target    string
	overwrite bool
	mode      uint32
	f         *os.File
	h         hash.Hash
	written   int64
	touched   time.Time
}

type uploads struct {
	dir string // records of in-progress temp files, so a crash can't strand them
	mu  sync.Mutex
	m   map[string]*upload
}

// newUploads removes temp files left by uploads that were in progress when a
// previous node process died, then starts the idle reaper.
func newUploads(dir string) (*uploads, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	recs, _ := os.ReadDir(dir)
	for _, r := range recs {
		rec := filepath.Join(dir, r.Name())
		if tmp, err := os.ReadFile(rec); err == nil && strings.HasPrefix(filepath.Base(string(tmp)), ".relay-up-") {
			os.Remove(string(tmp))
		}
		os.Remove(rec)
	}
	u := &uploads{dir: dir, m: map[string]*upload{}}
	go func() {
		for range time.Tick(time.Minute) {
			u.mu.Lock()
			for id, up := range u.m {
				up.mu.Lock()
				idle := time.Since(up.touched) > uploadIdle
				up.mu.Unlock()
				if idle {
					up.discard()
					delete(u.m, id)
					os.Remove(filepath.Join(u.dir, id))
				}
			}
			u.mu.Unlock()
		}
	}()
	return u, nil
}

func (up *upload) discard() {
	up.f.Close()
	os.Remove(up.f.Name())
}

func (u *uploads) take(id string) (*upload, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	up := u.m[id]
	if up == nil {
		return nil, fmt.Errorf("no upload %q (it may have been idle for over %s)", id, uploadIdle)
	}
	delete(u.m, id)
	os.Remove(filepath.Join(u.dir, id))
	return up, nil
}

func (a *nodeAgent) doStat(args StatArgs) (*StatResult, error) {
	p, err := a.resolve(args.Path)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return &StatResult{Path: p}, nil
	}
	if err != nil {
		return nil, err
	}
	return &StatResult{Path: p, Exists: true, Dir: st.IsDir(), Size: st.Size(), Mode: uint32(st.Mode().Perm())}, nil
}

// doWalk lists a directory tree. Symlinks are never followed, so the walk
// cannot leave the jail; they are reported as skipped.
func (a *nodeAgent) doWalk(args StatArgs) (*WalkResult, error) {
	root, err := a.resolve(args.Path)
	if err != nil {
		return nil, err
	}
	res := &WalkResult{Root: root, Entries: []WalkEntry{}}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			if !d.IsDir() {
				return fmt.Errorf("%s is not a directory", root)
			}
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if !d.IsDir() && !d.Type().IsRegular() {
			res.Skipped = append(res.Skipped, rel)
			return nil
		}
		if len(res.Entries) == maxWalkEntries {
			return fmt.Errorf("more than %d entries under %s; archive it first (e.g. tar or Compress-Archive) and transfer the archive", maxWalkEntries, root)
		}
		e := WalkEntry{Rel: rel, Dir: d.IsDir()}
		if info, err := d.Info(); err == nil {
			e.Size, e.Mode = info.Size(), uint32(info.Mode().Perm())
		}
		res.Entries = append(res.Entries, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (a *nodeAgent) doMkdir(args MkdirArgs) (*StatResult, error) {
	p, err := a.resolve(args.Path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(p, 0o755); err != nil {
		return nil, err
	}
	return &StatResult{Path: p, Exists: true, Dir: true}, nil
}

func (a *nodeAgent) doGetChunk(args GetChunkArgs) (*GetChunkResult, error) {
	p, err := a.resolve(args.Path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%s is a directory", p)
	}
	length := args.Length
	if length <= 0 || length > maxChunk {
		length = maxChunk
	}
	buf := make([]byte, length)
	n, err := f.ReadAt(buf, args.Offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return &GetChunkResult{Data: buf[:n], EOF: args.Offset+int64(n) >= st.Size()}, nil
}

func (a *nodeAgent) doPutOpen(args PutOpenArgs) (*PutOpenResult, error) {
	p, err := a.resolve(args.Path)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(p); err == nil {
		if st.IsDir() {
			return nil, fmt.Errorf("%s is a directory", p)
		}
		if !args.Overwrite {
			return nil, fmt.Errorf("%s already exists (set overwrite to replace it)", p)
		}
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, ".relay-up-*")
	if err != nil {
		return nil, err
	}
	idb := make([]byte, 8)
	rand.Read(idb)
	id := hex.EncodeToString(idb)
	if err := os.WriteFile(filepath.Join(a.uploads.dir, id), []byte(f.Name()), 0o600); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, err
	}
	a.uploads.mu.Lock()
	a.uploads.m[id] = &upload{target: p, overwrite: args.Overwrite, mode: args.Mode, f: f, h: sha256.New(), touched: time.Now()}
	a.uploads.mu.Unlock()
	return &PutOpenResult{UploadID: id, Path: p}, nil
}

func (a *nodeAgent) doPutChunk(args PutChunkArgs) (map[string]int64, error) {
	a.uploads.mu.Lock()
	up := a.uploads.m[args.UploadID]
	a.uploads.mu.Unlock()
	if up == nil {
		return nil, fmt.Errorf("no upload %q", args.UploadID)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if args.Offset != up.written {
		return nil, fmt.Errorf("chunk at offset %d, expected %d", args.Offset, up.written)
	}
	if _, err := up.f.Write(args.Data); err != nil {
		return nil, err
	}
	up.h.Write(args.Data)
	up.written += int64(len(args.Data))
	up.touched = time.Now()
	return map[string]int64{"written": up.written}, nil
}

func (a *nodeAgent) doPutClose(args PutCloseArgs) (*PutCloseResult, error) {
	up, err := a.uploads.take(args.UploadID)
	if err != nil {
		return nil, err
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	sum := hex.EncodeToString(up.h.Sum(nil))
	if args.SHA256 != "" && args.SHA256 != sum {
		up.discard()
		return nil, fmt.Errorf("sha256 mismatch for %s: got %s, sender says %s; nothing was written", up.target, sum, args.SHA256)
	}
	if err := up.f.Sync(); err != nil {
		up.discard()
		return nil, err
	}
	if err := up.f.Close(); err != nil {
		os.Remove(up.f.Name())
		return nil, err
	}
	if up.mode != 0 && runtime.GOOS != "windows" {
		os.Chmod(up.f.Name(), fs.FileMode(up.mode).Perm())
	}
	// Re-check: something may have created the target while we were writing.
	if _, err := os.Stat(up.target); err == nil && !up.overwrite {
		os.Remove(up.f.Name())
		return nil, fmt.Errorf("%s appeared during the transfer; not replacing it", up.target)
	}
	if err := os.Rename(up.f.Name(), up.target); err != nil {
		os.Remove(up.f.Name())
		return nil, err
	}
	return &PutCloseResult{Path: up.target, Bytes: up.written, SHA256: sum}, nil
}

func (a *nodeAgent) doPutAbort(args PutCloseArgs) (map[string]bool, error) {
	if up, err := a.uploads.take(args.UploadID); err == nil {
		up.discard()
	}
	return map[string]bool{"aborted": true}, nil
}
