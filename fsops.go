package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// OS-neutral file operations and the startup probe of the node's system.
// These behave the same on macOS, Linux and Windows, so an agent can manage
// files on any node without knowing its shell.

// probeCaseInsensitive asks the filesystem itself: create a lowercase-named
// file and look it up in uppercase. macOS volumes can go either way, and so
// can Linux (ext4 casefold) and Windows (per-directory case sensitivity).
func probeCaseInsensitive(dir string) bool {
	f, err := os.CreateTemp(dir, ".relay-case-probe-")
	if err != nil {
		// Read-only root: fall back to the platform default.
		return runtime.GOOS == "windows" || runtime.GOOS == "darwin"
	}
	name := f.Name()
	f.Close()
	defer os.Remove(name)
	upper := filepath.Join(filepath.Dir(name), strings.ToUpper(filepath.Base(name)))
	_, err = os.Stat(upper)
	return err == nil
}

func shellKind(shell string) string {
	if i := strings.LastIndexAny(shell, `/\`); i >= 0 {
		shell = shell[i+1:]
	}
	switch strings.TrimSuffix(strings.ToLower(shell), ".exe") {
	case "pwsh", "powershell":
		return "powershell"
	case "bash":
		return "bash"
	}
	return "sh"
}

// argvString renders argv for policy matching and logs, quoting arguments
// that contain spaces.
func argvString(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		if a == "" || strings.ContainsAny(a, " \t\"'") {
			a = `"` + strings.ReplaceAll(a, `"`, `\"`) + `"`
		}
		parts[i] = a
	}
	return strings.Join(parts, " ")
}

// lexical resolves p like resolve, except that the last element is not
// followed if it is a symlink: removing or moving a link must act on the
// link, not on whatever it points to.
func (a *nodeAgent) lexical(p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", errors.New("path is required")
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(a.roots[0], p)
	}
	p = filepath.Clean(p)
	parent, err := a.resolve(filepath.Dir(p))
	if err != nil {
		return "", err
	}
	full := filepath.Join(parent, filepath.Base(p))
	for _, r := range a.roots {
		if within(r, full) {
			return full, nil
		}
	}
	return "", fmt.Errorf("path %q is outside this node's roots %v", p, a.roots)
}

func (a *nodeAgent) isRoot(p string) bool {
	for _, r := range a.roots {
		if rel, err := filepath.Rel(r, p); err == nil && rel == "." {
			return true
		}
	}
	return false
}

func (a *nodeAgent) doStat(args StatArgs) (*StatResult, error) {
	res := &StatResult{}
	if lp, err := a.lexical(args.Path); err == nil {
		if li, err := os.Lstat(lp); err == nil && li.Mode()&fs.ModeSymlink != 0 {
			res.Symlink = true
		}
	}
	p, err := a.resolve(args.Path)
	if err != nil {
		return nil, err
	}
	res.Path = p
	st, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return res, nil
	}
	if err != nil {
		return nil, err
	}
	res.Exists, res.Dir, res.Size = true, st.IsDir(), st.Size()
	res.Mode, res.ModTime = uint32(st.Mode().Perm()), st.ModTime().UTC().Format(time.RFC3339)
	if args.Hash && !st.IsDir() {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return nil, err
		}
		res.SHA256 = hex.EncodeToString(h.Sum(nil))
	}
	return res, nil
}

func (a *nodeAgent) doMove(args MoveArgs) (*StatResult, error) {
	src, err := a.lexical(args.Src)
	if err != nil {
		return nil, err
	}
	dst, err := a.lexical(args.Dst)
	if err != nil {
		return nil, err
	}
	if a.isRoot(src) {
		return nil, errors.New("refusing to move a node root")
	}
	if _, err := os.Lstat(src); err != nil {
		return nil, err
	}
	if st, err := os.Lstat(dst); err == nil {
		// A case-only rename on a case-insensitive filesystem finds itself.
		if same, _ := sameFile(src, dst); !same {
			if st.IsDir() {
				return nil, fmt.Errorf("%s is an existing directory; give the full new path", dst)
			}
			if !args.Overwrite {
				return nil, fmt.Errorf("%s already exists (set overwrite to replace it)", dst)
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return nil, err
	}
	if err := os.Rename(src, dst); err != nil {
		var le *os.LinkError
		if errors.As(err, &le) && isCrossDevice(le.Err) {
			return nil, fmt.Errorf("%s and %s are on different volumes; use transfer, then fs_remove", src, dst)
		}
		return nil, err
	}
	return a.doStat(StatArgs{Path: dst})
}

func sameFile(a, b string) (bool, error) {
	sa, err := os.Lstat(a)
	if err != nil {
		return false, err
	}
	sb, err := os.Lstat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(sa, sb), nil
}

func (a *nodeAgent) doRemove(args RemoveArgs) (map[string]any, error) {
	p, err := a.lexical(args.Path)
	if err != nil {
		return nil, err
	}
	if a.isRoot(p) {
		return nil, errors.New("refusing to remove a node root")
	}
	st, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if st.IsDir() && args.Recursive {
		// RemoveAll does not follow symlinks inside the tree.
		err = os.RemoveAll(p)
	} else {
		err = os.Remove(p)
		if err != nil && st.IsDir() {
			err = fmt.Errorf("%s is a non-empty directory (set recursive to remove it and everything in it)", p)
		}
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"removed": p, "dir": st.IsDir(), "symlink": st.Mode()&fs.ModeSymlink != 0}, nil
}

// walkFiles visits regular files and directories under root without
// following symlinks, giving each its slash-separated relative path.
func walkFiles(root string, fn func(rel string, d fs.DirEntry) error) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root {
				return err
			}
			return nil // unreadable entry: skip it, keep going
		}
		if p == root {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		return fn(filepath.ToSlash(rel), d)
	})
}

var errStop = errors.New("stop")

func (a *nodeAgent) caseInsensitiveAt(p string) bool {
	for i, r := range a.roots {
		if within(r, p) && i < len(a.info.RootsCaseInsensitive) {
			return a.info.RootsCaseInsensitive[i]
		}
	}
	return false
}

func (a *nodeAgent) doGlob(args GlobArgs) (*GlobResult, error) {
	root, err := a.resolve(args.Path)
	if err != nil {
		return nil, err
	}
	if args.Pattern == "" {
		return nil, errors.New("pattern is required, e.g. **/*.go")
	}
	res, err := compileGlobs([]string{strings.ReplaceAll(args.Pattern, `\`, "/")}, a.caseInsensitiveAt(root))
	if err != nil {
		return nil, err
	}
	re := res[0]
	limit := args.Max
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	out := &GlobResult{Root: root, Matches: []string{}}
	err = walkFiles(root, func(rel string, d fs.DirEntry) error {
		if re.MatchString(rel) {
			if len(out.Matches) == limit {
				out.Truncated = true
				return errStop
			}
			if d.IsDir() {
				rel += "/"
			}
			out.Matches = append(out.Matches, rel)
		}
		return nil
	})
	if err != nil && err != errStop {
		return nil, err
	}
	return out, nil
}

const maxGrepFile = 10 << 20

func (a *nodeAgent) doGrep(args GrepArgs) (*GrepResult, error) {
	root, err := a.resolve(args.Path)
	if err != nil {
		return nil, err
	}
	expr := args.Pattern
	if args.IgnoreCase {
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("pattern: %v", err)
	}
	var filter *regexp.Regexp
	if args.Glob != "" {
		gs, err := compileGlobs([]string{strings.ReplaceAll(args.Glob, `\`, "/")}, a.caseInsensitiveAt(root))
		if err != nil {
			return nil, err
		}
		filter = gs[0]
	}
	limit := args.Max
	if limit <= 0 || limit > 2000 {
		limit = 200
	}
	out := &GrepResult{Root: root, Matches: []GrepMatch{}}

	grepFile := func(path, rel string) error {
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		head := make([]byte, 8192)
		n, _ := io.ReadFull(f, head)
		if bytes.IndexByte(head[:n], 0) >= 0 {
			out.Skipped++
			return nil
		}
		f.Seek(0, io.SeekStart)
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for line := 1; sc.Scan(); line++ {
			text := strings.TrimSuffix(sc.Text(), "\r")
			if !re.MatchString(text) {
				continue
			}
			if len(out.Matches) == limit {
				out.Truncated = true
				return errStop
			}
			if len(text) > 300 {
				text = strings.ToValidUTF8(text[:300], "") + "…"
			}
			out.Matches = append(out.Matches, GrepMatch{File: rel, Line: line, Text: text})
		}
		return nil
	}

	st, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		err = grepFile(root, filepath.Base(root))
	} else {
		err = walkFiles(root, func(rel string, d fs.DirEntry) error {
			if !d.Type().IsRegular() || filter != nil && !filter.MatchString(rel) {
				return nil
			}
			if info, err := d.Info(); err != nil || info.Size() > maxGrepFile {
				out.Skipped++
				return nil
			}
			return grepFile(filepath.Join(root, filepath.FromSlash(rel)), rel)
		})
	}
	if err != nil && err != errStop {
		return nil, err
	}
	return out, nil
}
