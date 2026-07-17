package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSeenOrRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dedupe.json")
	d, err := Open(path, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if seen, _ := d.SeenOrRecord("job-1"); seen {
		t.Error("first sighting should not be seen")
	}
	if seen, _ := d.SeenOrRecord("job-1"); !seen {
		t.Error("second sighting should be seen")
	}
	if seen, _ := d.SeenOrRecord("job-2"); seen {
		t.Error("different job should not be seen")
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dedupe.json")
	d1, _ := Open(path, time.Minute)
	d1.SeenOrRecord("job-x")

	d2, err := Open(path, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if seen, _ := d2.SeenOrRecord("job-x"); !seen {
		t.Error("expected job-x to survive a reopen (idempotency across restarts)")
	}
}

func TestTTLExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dedupe.json")
	d, _ := Open(path, time.Minute)
	// Force a deterministic clock.
	base := time.Unix(1_000_000, 0)
	d.now = func() time.Time { return base }
	d.SeenOrRecord("old")

	// Advance beyond the TTL; the old id should no longer count as seen.
	d.now = func() time.Time { return base.Add(2 * time.Minute) }
	if seen, _ := d.SeenOrRecord("old"); seen {
		t.Error("expired id should not be seen")
	}
}
