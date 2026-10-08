package api

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// fakeLpass stands in for the lpass binary. A write command (edit, rm) fails
// if it runs while any other lpass command is running; a read command (show)
// fails only if it runs during a write.
const fakeLpass = `#!/bin/sh
dir="$FAKE_LPASS_DIR"
case "$1" in
edit|rm)
	cat >/dev/null
	mkdir "$dir/write" 2>/dev/null || { echo "overlap: concurrent write" >&2; exit 1; }
	if [ -n "$(ls "$dir/reads")" ]; then rmdir "$dir/write"; echo "overlap: write during read" >&2; exit 1; fi
	sleep 0.05
	rmdir "$dir/write"
	;;
show)
	touch "$dir/reads/$$"
	if [ -d "$dir/write" ]; then rm "$dir/reads/$$"; echo "overlap: read during write" >&2; exit 1; fi
	sleep 0.02
	rm "$dir/reads/$$"
	echo '[{"id":"1","name":"n","fullname":"g/n","note":""}]'
	;;
esac
`

func TestVaultCommandsDoNotOverlapWrites(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "reads"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lpass"), []byte(fakeLpass), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_LPASS_DIR", dir)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	c := &Client{loggedIn: true}
	var wg sync.WaitGroup
	errs := make(chan error, 60)
	for i := 0; i < 20; i++ {
		id := fmt.Sprint(i)
		wg.Add(3)
		go func() {
			defer wg.Done()
			errs <- c.Update(Secret{ID: id, Name: "n"})
		}()
		go func() {
			defer wg.Done()
			_, err := c.Read(id)
			errs <- err
		}()
		go func() {
			defer wg.Done()
			errs <- c.Delete(id)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("lpass commands overlapped: %v", err)
		}
	}
}
