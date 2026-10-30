package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// relay update fetches the newest release for this OS from GitHub, checks it
// against the release's SHA256SUMS, and puts it in place of this copy and of
// ~/.relay/bin/relay, the copy background services run. Services are stopped
// for the swap and started again, so they run the new version right away.
//
// A service keeps running the copy it was installed with, so without this a
// newer download changes nothing in the background: that copy is replaced
// only by relay update or another relay service install.

const releaseRepo = "izy1sky/ghostrelay"

func runUpdate(args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	check := fs.Bool("check", false, "only say whether a newer version exists")
	fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	latest, err := latestRelease(ctx)
	if err != nil {
		log.Fatal(err)
	}
	svc := serviceVersion()
	fmt.Printf("this copy: %s   background services: %s   newest release: %s\n", version, firstNonEmpty(svc, "none"), latest)
	switch {
	case newerVersion(latest, version):
		if *check {
			fmt.Println("run relay update to get it")
			return
		}
		fmt.Printf("downloading relay %s for %s/%s ... ", latest, runtime.GOOS, runtime.GOARCH)
		bin, err := downloadRelease(ctx, latest)
		if err != nil {
			fmt.Println("failed")
			log.Fatal(err)
		}
		defer os.Remove(bin)
		fmt.Println("checksum ok")
		done, err := installBinary(bin)
		reportInstall(done, err)
	case svc != "" && newerVersion(version, svc):
		if *check {
			fmt.Println("the services run an older copy; relay update puts this one in their place")
			return
		}
		self, _ := os.Executable()
		done, err := installBinary(self)
		reportInstall(done, err)
	default:
		fmt.Println("up to date")
	}
}

func reportInstall(done []string, err error) {
	for _, d := range done {
		fmt.Println("  updated " + d)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func githubGet(ctx context.Context, url string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "relay/"+version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("couldn't reach GitHub: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub: %s for %s", resp.Status, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 200<<20))
}

// latestRelease returns the newest release's version, without the "v".
func latestRelease(ctx context.Context) (string, error) {
	b, err := githubGet(ctx, "https://api.github.com/repos/"+releaseRepo+"/releases/latest")
	if err != nil {
		return "", err
	}
	var rel struct {
		Tag string `json:"tag_name"`
	}
	if err := json.Unmarshal(b, &rel); err != nil || rel.Tag == "" {
		return "", errors.New("GitHub gave no release")
	}
	return strings.TrimPrefix(rel.Tag, "v"), nil
}

// parseVersion reads "0.8.1" or "v0.8.0-dev"; a -suffix is older than none.
func parseVersion(v string) (nums [3]int, pre bool, ok bool) {
	v = strings.TrimPrefix(v, "v")
	v, suffix, _ := strings.Cut(v, "-")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return nums, false, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nums, false, false
		}
		nums[i] = n
	}
	return nums, suffix != "", true
}

// newerVersion reports whether a is a later version than b.
func newerVersion(a, b string) bool {
	na, pa, oka := parseVersion(a)
	nb, pb, okb := parseVersion(b)
	if !oka || !okb {
		return false
	}
	for i := range na {
		if na[i] != nb[i] {
			return na[i] > nb[i]
		}
	}
	return pb && !pa
}

func releaseAsset(v string) string {
	ext := ".tar.gz"
	if runtime.GOOS == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("relay_%s_%s_%s%s", v, runtime.GOOS, runtime.GOARCH, ext)
}

// downloadRelease fetches release v for this platform, checks it against
// SHA256SUMS and returns the path of the unpacked binary (a temporary file).
func downloadRelease(ctx context.Context, v string) (string, error) {
	base := "https://github.com/" + releaseRepo + "/releases/download/v" + v + "/"
	name := releaseAsset(v)
	sums, err := githubGet(ctx, base+"SHA256SUMS")
	if err != nil {
		return "", err
	}
	want := ""
	for _, line := range strings.Split(string(sums), "\n") {
		if f := strings.Fields(line); len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			want = f[0]
		}
	}
	if want == "" {
		return "", fmt.Errorf("release %s has no %s", v, name)
	}
	archive, err := githubGet(ctx, base+name)
	if err != nil {
		return "", err
	}
	if sum := sha256.Sum256(archive); hex.EncodeToString(sum[:]) != want {
		return "", fmt.Errorf("%s doesn't match SHA256SUMS; not installing it", name)
	}
	bin, err := unpackBinary(archive, strings.HasSuffix(name, ".zip"))
	if err != nil {
		return "", fmt.Errorf("%s: %v", name, err)
	}
	f, err := os.CreateTemp("", "relay-update-*")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(bin); err != nil {
		return "", err
	}
	return f.Name(), os.Chmod(f.Name(), 0o755)
}

// unpackBinary finds relay (or relay.exe) in a release archive.
func unpackBinary(archive []byte, isZip bool) ([]byte, error) {
	exe := "relay"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	if isZip {
		zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if filepath.Base(f.Name) == exe && !f.FileInfo().IsDir() {
				rc, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer rc.Close()
				return io.ReadAll(io.LimitReader(rc, 200<<20))
			}
		}
		return nil, fmt.Errorf("no %s inside", exe)
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			return nil, fmt.Errorf("no %s inside", exe)
		}
		if filepath.Base(h.Name) == exe && h.Typeflag == tar.TypeReg {
			return io.ReadAll(io.LimitReader(tr, 200<<20))
		}
	}
}

// serviceVersion is the version of ~/.relay/bin/relay, the copy services run,
// or "" when there is none.
func serviceVersion() string {
	exe := serviceExe()
	if _, err := os.Stat(exe); err != nil {
		return ""
	}
	out, err := exec.Command(exe, "version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// installBinary puts bin in place of the services' copy and of this copy,
// stopping installed services for the swap and starting them again.
func installBinary(bin string) ([]string, error) {
	var done []string
	var running []*service
	for _, role := range []string{"node", "server"} {
		if s, err := newService(role, ""); err == nil && s.installed() {
			s.stop()
			running = append(running, s)
		}
	}
	svcExe := serviceExe()
	var firstErr error
	if _, err := os.Stat(svcExe); err == nil || len(running) > 0 {
		if err := replaceFile(svcExe, bin); err != nil {
			firstErr = err
		} else {
			done = append(done, svcExe+" (what background services run)")
		}
	}
	for _, s := range running {
		if err := s.start(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("restart %s: %v", s.id, err)
		} else if err == nil {
			done = append(done, s.id+" restarted")
		}
	}
	self, err := os.Executable()
	if err == nil {
		self, _ = filepath.EvalSymlinks(self)
		svc, _ := filepath.EvalSymlinks(svcExe)
		src, _ := filepath.EvalSymlinks(bin)
		if self != svc && self != src {
			if err := replaceFile(self, bin); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("replace %s: %v", self, err)
			} else if err == nil {
				done = append(done, self)
			}
		}
	}
	return done, firstErr
}

// replaceFile copies src over dst. dst may be running: it is renamed out of
// the way first (Windows allows renaming a running .exe, not overwriting it).
func replaceFile(dst, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	out.Close()
	old := dst + ".old"
	os.Remove(old)
	os.Rename(dst, old)
	if err := os.Rename(tmp, dst); err != nil {
		os.Rename(old, dst)
		os.Remove(tmp)
		return err
	}
	os.Remove(old) // fails for a running .exe on Windows; the next update removes it
	return nil
}
