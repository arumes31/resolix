package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// TestSourceFilesStayReviewable keeps implementation and test files small
// enough to review as cohesive units. Split by responsibility instead of
// raising these limits when a file outgrows its budget.
func TestSourceFilesStayReviewable(t *testing.T) {
	t.Parallel()

	limits := map[string]int{
		".css":  1200,
		".go":   1000,
		".html": 800,
		".js":   600,
	}
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate architecture test")
	}
	root := filepath.Dir(currentFile)
	oversized := []string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}

		limit, tracked := limits[strings.ToLower(filepath.Ext(path))]
		if !tracked || strings.HasSuffix(strings.ToLower(path), ".min.js") {
			return nil
		}
		lines, err := sourceLineCount(path)
		if err != nil {
			return err
		}
		if lines > limit {
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			oversized = append(oversized, fmt.Sprintf("%s: %d lines (limit %d)", filepath.ToSlash(relative), lines, limit))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(oversized) == 0 {
		return
	}
	sort.Strings(oversized)
	t.Fatalf("source files exceed their reviewability budget; split them by cohesive responsibility:\n%s", strings.Join(oversized, "\n"))
}

func sourceLineCount(path string) (int, error) {
	content, err := os.ReadFile(path) // #nosec G304 -- paths come from the repository walk above
	if err != nil {
		return 0, err
	}
	if len(content) == 0 {
		return 0, nil
	}
	lines := bytes.Count(content, []byte{'\n'})
	if content[len(content)-1] != '\n' {
		lines++
	}
	return lines, nil
}
