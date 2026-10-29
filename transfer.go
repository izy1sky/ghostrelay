package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// transfer copies a file or a directory tree from one node to another,
// streaming chunks through the server. Policy-wise it is a read of every
// source file plus a write of every destination file, checked before any
// byte moves.

const transferChunk = 1 << 20

type TransferArgs struct {
	SrcNode   string `json:"src_node"`
	SrcPath   string `json:"src_path"`
	DstNode   string `json:"dst_node"`
	DstPath   string `json:"dst_path"`
	Overwrite bool   `json:"overwrite,omitempty"`
}

type transferFile struct {
	src, dst string
	size     int64
	mode     uint32
}

// callTimeout bounds one node call; the transfer as a whole is bounded only by
// the caller's request context.
func callTimeout(ctx context.Context, nc *nodeConn, op string, args, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return nc.call(ctx, op, args, out)
}

// joinNode appends a slash-separated relative path to a node path; the node
// cleans it, and Windows accepts forward slashes.
func joinNode(base, rel string) string {
	return strings.TrimRight(base, `/\`) + "/" + rel
}

func baseName(p, nodeOS string) string {
	seps := "/"
	if nodeOS == "windows" {
		seps = `/\`
	}
	p = strings.TrimRight(p, seps)
	if i := strings.LastIndexAny(p, seps); i >= 0 {
		return p[i+1:]
	}
	return p
}

func (s *server) runTransfer(ctx context.Context, agent string, raw json.RawMessage) (string, string, error) {
	var args TransferArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return "", "", err
	}
	if args.SrcNode == "" || args.DstNode == "" || args.SrcPath == "" || args.DstPath == "" {
		return "", "", fmt.Errorf("src_node, src_path, dst_node and dst_path are all required")
	}
	src, err := s.node(args.SrcNode)
	if err != nil {
		return "", "", err
	}
	dst, err := s.node(args.DstNode)
	if err != nil {
		return "", "", err
	}
	pol := s.pol.Load()
	readReq := func(p string) policyReq {
		return buildReq(agent, "fs_read", mustJSON(map[string]string{"path": p}), src)
	}
	writeReq := func(p string) policyReq {
		return buildReq(agent, "fs_write", mustJSON(map[string]string{"path": p}), dst)
	}

	// Refuse early, before touching the source, if reading it is denied.
	if v := pol.eval(readReq(args.SrcPath)); !pol.none && v.Action == actDeny {
		return "", v.String(), fmt.Errorf("denied by policy %s: reading %s on %s", v, args.SrcPath, src.info.Name)
	}

	var st StatResult
	if err := callTimeout(ctx, src, "fs_stat", StatArgs{Path: args.SrcPath}, &st); err != nil {
		return "", "", err
	}
	if !st.Exists {
		return "", "", fmt.Errorf("%s does not exist on %s", args.SrcPath, src.info.Name)
	}
	var dstSt StatResult
	if err := callTimeout(ctx, dst, "fs_stat", StatArgs{Path: args.DstPath}, &dstSt); err != nil {
		return "", "", err
	}

	// Work out every (source, destination) pair, cp -r style.
	var files []transferFile
	var dirs []string
	var skipped []string
	if !st.Dir {
		target := dstSt.Path
		if dstSt.Exists && dstSt.Dir {
			target = joinNode(dstSt.Path, baseName(st.Path, src.info.OS))
			var t StatResult
			if err := callTimeout(ctx, dst, "fs_stat", StatArgs{Path: target}, &t); err != nil {
				return "", "", err
			}
			dstSt = t
		}
		if dstSt.Exists && dstSt.Dir {
			return "", "", fmt.Errorf("%s on %s is a directory", target, dst.info.Name)
		}
		if dstSt.Exists && !args.Overwrite {
			return "", "", fmt.Errorf("%s already exists on %s (set overwrite to replace it)", target, dst.info.Name)
		}
		files = append(files, transferFile{src: st.Path, dst: target, size: st.Size, mode: st.Mode})
	} else {
		if dstSt.Exists && !dstSt.Dir {
			return "", "", fmt.Errorf("%s on %s is a file, but the source is a directory", dstSt.Path, dst.info.Name)
		}
		if dstSt.Exists && !args.Overwrite {
			return "", "", fmt.Errorf("%s already exists on %s (set overwrite to merge into it, replacing files with the same name)", dstSt.Path, dst.info.Name)
		}
		var w WalkResult
		if err := callTimeout(ctx, src, "fs_walk", StatArgs{Path: st.Path}, &w); err != nil {
			return "", "", err
		}
		skipped = w.Skipped
		dirs = append(dirs, dstSt.Path)
		for _, e := range w.Entries {
			if e.Dir {
				dirs = append(dirs, joinNode(dstSt.Path, e.Rel))
				continue
			}
			files = append(files, transferFile{src: joinNode(w.Root, e.Rel), dst: joinNode(dstSt.Path, e.Rel), size: e.Size, mode: e.Mode})
		}
	}

	var total int64
	var reqs []policyReq
	for _, d := range dirs {
		reqs = append(reqs, writeReq(d))
	}
	for _, f := range files {
		total += f.size
		reqs = append(reqs, readReq(f.src), writeReq(f.dst))
	}
	what := fmt.Sprintf("%s:%s → %s:%s (%d files, %s)", src.info.Name, st.Path, dst.info.Name, dstSt.Path, len(files), humanBytes(total))
	display := policyReq{Agent: agent, Tool: "transfer", Node: src.info.Name + "→" + dst.info.Name, HasPath: true, Path: what}
	note, err := s.authorizeMany(ctx.Done(), reqs, display)
	if err != nil {
		return "", note, err
	}

	start := time.Now()
	for _, d := range dirs {
		var r StatResult
		if err := callTimeout(ctx, dst, "fs_mkdir", MkdirArgs{Path: d}, &r); err != nil {
			return "", note, fmt.Errorf("mkdir %s on %s: %v", d, dst.info.Name, err)
		}
	}
	var moved int64
	var lastSum string
	for i, f := range files {
		n, sum, err := s.copyFile(ctx, src, dst, f, args.Overwrite)
		if err != nil {
			return "", note, fmt.Errorf("copying %s: %v (%d of %d files copied before this, %s)", f.src, err, i, len(files), humanBytes(moved))
		}
		moved += n
		lastSum = sum
	}

	secs := time.Since(start).Seconds()
	var b strings.Builder
	fmt.Fprintf(&b, "copied %s in %.1fs (%s/s)\n", what, secs, humanBytes(int64(float64(moved)/max(secs, 0.001))))
	if len(files) == 1 && !st.Dir {
		fmt.Fprintf(&b, "sha256 %s (verified on %s)\n", lastSum, dst.info.Name)
	} else {
		b.WriteString("every file's sha256 was verified on the destination\n")
	}
	if len(skipped) > 0 {
		fmt.Fprintf(&b, "skipped %d symlinks/special files: %s\n", len(skipped), strings.Join(skipped[:min(len(skipped), 10)], ", "))
	}
	return b.String(), note, nil
}

// copyFile streams one file. Reading the next chunk overlaps with writing the
// current one; the destination checks size and sha256 before renaming.
func (s *server) copyFile(ctx context.Context, src, dst *nodeConn, f transferFile, overwrite bool) (int64, string, error) {
	var open PutOpenResult
	if err := callTimeout(ctx, dst, "put_open", PutOpenArgs{Path: f.dst, Mode: f.mode, Overwrite: overwrite}, &open); err != nil {
		return 0, "", err
	}
	ok := false
	defer func() {
		if !ok {
			var r map[string]bool
			callTimeout(context.Background(), dst, "put_abort", PutCloseArgs{UploadID: open.UploadID}, &r)
		}
	}()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	chunks := make(chan []byte, 4)
	readErr := make(chan error, 1)
	go func() {
		defer close(chunks)
		var off int64
		for {
			var r GetChunkResult
			if err := callTimeout(ctx, src, "get_chunk", GetChunkArgs{Path: f.src, Offset: off, Length: transferChunk}, &r); err != nil {
				readErr <- err
				return
			}
			if len(r.Data) > 0 {
				select {
				case chunks <- r.Data:
				case <-ctx.Done():
					readErr <- ctx.Err()
					return
				}
				off += int64(len(r.Data))
			}
			if r.EOF || len(r.Data) == 0 {
				readErr <- nil
				return
			}
		}
	}()

	h := sha256.New()
	var off int64
	for data := range chunks {
		h.Write(data)
		var r map[string]int64
		if err := callTimeout(ctx, dst, "put_chunk", PutChunkArgs{UploadID: open.UploadID, Offset: off, Data: data}, &r); err != nil {
			cancel()
			return off, "", err
		}
		off += int64(len(data))
	}
	if err := <-readErr; err != nil {
		return off, "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	var closed PutCloseResult
	if err := callTimeout(ctx, dst, "put_close", PutCloseArgs{UploadID: open.UploadID, SHA256: sum}, &closed); err != nil {
		return off, "", err
	}
	ok = true
	return off, sum, nil
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
