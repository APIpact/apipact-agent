// Package store provides a small persistent set of processed job ids so that
// at-least-once redelivery stays idempotent across agent restarts. The envelope
// layer's in-memory ReplayCache handles the crypto-replay window; this store
// additionally survives restarts and keys on the application-level job id.
package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Dedupe is a TTL set of job ids backed by a JSON file. It is safe for
// concurrent use. Writes are atomic (temp + rename).
type Dedupe struct {
	path string
	ttl  time.Duration
	now  func() time.Time

	mu   sync.Mutex
	seen map[string]int64 // jobID -> unix seconds when recorded
}

type persisted struct {
	Seen map[string]int64 `json:"seen"`
}

// Open loads (or creates) a dedupe store at path retaining ids for ttl.
func Open(path string, ttl time.Duration) (*Dedupe, error) {
	d := &Dedupe{path: path, ttl: ttl, now: time.Now, seen: map[string]int64{}}
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-controlled state dir
	if err != nil {
		if os.IsNotExist(err) {
			return d, nil
		}
		return nil, err
	}
	var p persisted
	if json.Unmarshal(raw, &p) == nil && p.Seen != nil {
		d.seen = p.Seen
	}
	d.pruneLocked()
	return d, nil
}

// SeenOrRecord returns true if jobID was already processed (within the TTL);
// otherwise it records it and returns false. The record is persisted before
// returning false so a crash mid-execution still suppresses the duplicate.
func (d *Dedupe) SeenOrRecord(jobID string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	nowSec := d.now().Unix()
	if ts, ok := d.seen[jobID]; ok && nowSec-ts < int64(d.ttl.Seconds()) {
		return true, nil
	}
	d.pruneLocked()
	d.seen[jobID] = nowSec
	if err := d.flushLocked(); err != nil {
		// Roll back the in-memory record so a caller that treats the error as
		// fatal does not leave a phantom entry.
		delete(d.seen, jobID)
		return false, err
	}
	return false, nil
}

func (d *Dedupe) pruneLocked() {
	cutoff := d.now().Unix() - int64(d.ttl.Seconds())
	for id, ts := range d.seen {
		if ts < cutoff {
			delete(d.seen, id)
		}
	}
}

func (d *Dedupe) flushLocked() error {
	raw, err := json.Marshal(persisted{Seen: d.seen})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(d.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(d.path), ".dedupe-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, d.path)
}
