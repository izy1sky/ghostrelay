package main

import "encoding/json"

// Frame types on the node link. See PROTOCOL.md.
const (
	msgHello   = "hello"
	msgWelcome = "welcome"
	msgReq     = "req"
	msgRes     = "res"
	msgCancel  = "cancel"
)

// maxFrame bounds a single WebSocket message in either direction.
const maxFrame = 64 << 20

type Msg struct {
	Type   string          `json:"type"`
	ID     string          `json:"id,omitempty"`
	Op     string          `json:"op,omitempty"`
	Args   json.RawMessage `json:"args,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
	Info   *NodeInfo       `json:"info,omitempty"`
}

type NodeInfo struct {
	Name       string            `json:"name"`
	Version    string            `json:"version"`
	OS         string            `json:"os"`
	Arch       string            `json:"arch"`
	Hostname   string            `json:"hostname"`
	Shell      string            `json:"shell"`
	Roots      []string          `json:"roots"`
	AllowExec  bool              `json:"allow_exec"`
	MaxOutput  int               `json:"max_output"`
	MaxTimeout int               `json:"max_timeout_sec"`
	MaxJobs    int               `json:"max_jobs"`
	MaxJobTime int               `json:"max_job_timeout_sec"`
	Tools      map[string]string `json:"tools,omitempty"`
}

type ExecArgs struct {
	Command    string `json:"command"`
	Cwd        string `json:"cwd,omitempty"`
	TimeoutSec int    `json:"timeout_sec,omitempty"`
	Background bool   `json:"background,omitempty"`
	Owner      string `json:"owner,omitempty"` // set by the server to the calling agent's name
}

type ExecResult struct {
	ExitCode        int    `json:"exit_code"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
	TimedOut        bool   `json:"timed_out,omitempty"`
	DurationMs      int64  `json:"duration_ms"`
}

type ReadArgs struct {
	Path   string `json:"path"`
	Offset int    `json:"offset,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

type ReadResult struct {
	Path       string `json:"path"`
	Content    string `json:"content"`
	StartLine  int    `json:"start_line"`
	TotalLines int    `json:"total_lines"`
	Truncated  bool   `json:"truncated,omitempty"`
	CRLF       bool   `json:"crlf,omitempty"`
}

type WriteArgs struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type WriteResult struct {
	Path  string `json:"path"`
	Bytes int    `json:"bytes"`
}

type EditArgs struct {
	Path       string `json:"path"`
	OldString  string `json:"old_string"`
	NewString  string `json:"new_string"`
	ReplaceAll bool   `json:"replace_all,omitempty"`
}

type EditResult struct {
	Path         string `json:"path"`
	Replacements int    `json:"replacements"`
}

type ListArgs struct {
	Path string `json:"path,omitempty"`
}

type ListEntry struct {
	Name    string `json:"name"`
	Dir     bool   `json:"dir"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
}

type ListResult struct {
	Path      string      `json:"path"`
	Entries   []ListEntry `json:"entries"`
	Truncated bool        `json:"truncated,omitempty"`
}

// Background jobs. A job outlives the link that started it; its output goes to
// a log file on the node and is read back in chunks by byte offset.

type JobInfo struct {
	ID          string `json:"id"`
	Command     string `json:"command"`
	Cwd         string `json:"cwd"`
	Owner       string `json:"owner,omitempty"`
	PID         int    `json:"pid"`
	State       string `json:"state"` // running | exited | killed | timed_out
	ExitCode    *int   `json:"exit_code,omitempty"`
	Started     string `json:"started"`
	Ended       string `json:"ended,omitempty"`
	DurationMs  int64  `json:"duration_ms"`
	OutputBytes int64  `json:"output_bytes"`
}

type JobArgs struct {
	ID string `json:"job_id"`
}

type JobLogsArgs struct {
	ID       string `json:"job_id"`
	Offset   int64  `json:"offset,omitempty"`
	MaxBytes int    `json:"max_bytes,omitempty"`
	Tail     bool   `json:"tail,omitempty"`
	WaitSec  int    `json:"wait_sec,omitempty"`
}

type JobLogsResult struct {
	Job        JobInfo `json:"job"`
	Data       string  `json:"data"`
	Offset     int64   `json:"offset"`
	NextOffset int64   `json:"next_offset"`
	More       bool    `json:"more,omitempty"` // output beyond next_offset already exists
}

type JobsListResult struct {
	Jobs []JobInfo `json:"jobs"`
}

// File transfer. The server streams a file from one node to another in
// chunks: get_chunk on the source, put_open/put_chunk/put_close on the
// destination. []byte fields travel base64-encoded.

type StatArgs struct {
	Path string `json:"path"`
}

type StatResult struct {
	Path   string `json:"path"` // resolved, in the node's own separators
	Exists bool   `json:"exists"`
	Dir    bool   `json:"dir,omitempty"`
	Size   int64  `json:"size,omitempty"`
	Mode   uint32 `json:"mode,omitempty"` // permission bits
}

type WalkEntry struct {
	Rel  string `json:"rel"` // relative to the walked root, with forward slashes
	Dir  bool   `json:"dir,omitempty"`
	Size int64  `json:"size,omitempty"`
	Mode uint32 `json:"mode,omitempty"`
}

type WalkResult struct {
	Root    string      `json:"root"`
	Entries []WalkEntry `json:"entries"`
	Skipped []string    `json:"skipped,omitempty"` // symlinks and special files
}

type MkdirArgs struct {
	Path string `json:"path"`
}

type GetChunkArgs struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset"`
	Length int    `json:"length"`
}

type GetChunkResult struct {
	Data []byte `json:"data"`
	EOF  bool   `json:"eof"`
}

type PutOpenArgs struct {
	Path      string `json:"path"`
	Mode      uint32 `json:"mode,omitempty"`
	Overwrite bool   `json:"overwrite,omitempty"`
}

type PutOpenResult struct {
	UploadID string `json:"upload_id"`
	Path     string `json:"path"`
}

type PutChunkArgs struct {
	UploadID string `json:"upload_id"`
	Offset   int64  `json:"offset"`
	Data     []byte `json:"data"`
}

type PutCloseArgs struct {
	UploadID string `json:"upload_id"`
	SHA256   string `json:"sha256"`
}

type PutCloseResult struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}
