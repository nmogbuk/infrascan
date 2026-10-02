// Package infrascan is the read-only decision layer that gates provisioning: it
// scans a checked-out repo and reports which infra primitives the app actually
// uses, so a platform provisions only what is needed instead of standing up (and paying
// for) stacks nobody uses.
//
// Detect is pure: it only reads files under the given path. It performs no
// deploys, no DB writes, and no network I/O. The caller decides what to do with a Plan.
package infrascan

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// Need is an infra capability a repo may depend on.
type Need string

const (
	NeedSupabase      Need = "supabase"       // supabase client → per-team Supabase stack
	NeedPostgres      Need = "postgres"       // direct (non-Supabase) Postgres → shared cluster, per-project DB
	NeedRedis         Need = "redis"          // redis / valkey → shared cache
	NeedQueue         Need = "queue"          // rabbitmq / amqp → shared queue
	NeedObjectStorage Need = "object_storage" // S3 / MinIO SDK → per-project bucket on shared MinIO
)

// Signal is the evidence behind a "yes" — which file and which token triggered
// the detection. Every true flag in a Plan has at least one Signal, so the
// decision is always explainable.
type Signal struct {
	Need    Need   `json:"need"`
	File    string `json:"file"`    // path relative to the repo root, slash-separated
	Pattern string `json:"pattern"` // the dependency or token that matched
}

// Plan is the declarative outcome of a scan: capability flags plus the evidence
// for each one.
type Plan struct {
	Supabase      bool     `json:"supabase"`
	Postgres      bool     `json:"postgres"`
	Redis         bool     `json:"redis"`
	Queue         bool     `json:"queue"`
	ObjectStorage bool     `json:"object_storage"`
	Signals       []Signal `json:"signals"`
}

const (
	maxManifestBytes = 4 << 20 // dependency manifests are small; cap defensively
	maxSourceBytes   = 1 << 20 // bound per-source-file scanning
)

// Detect scans the checked-out repo at repoPath and returns the infra it uses.
// It is conservative and explainable: every true flag carries the file+pattern
// that triggered it, and anything ambiguous is left false (cheaper to opt in on
// the next scan than to provision unused infra). It only reads files — no
// deploys, no DB, no network.
func Detect(ctx context.Context, repoPath string) (Plan, error) {
	info, err := os.Stat(repoPath)
	if err != nil {
		return Plan{}, fmt.Errorf("infrascan: stat repo path: %w", err)
	}
	if !info.IsDir() {
		return Plan{}, fmt.Errorf("infrascan: repo path %q is not a directory", repoPath)
	}

	candidates := map[Need][]Signal{}
	add := func(sigs ...Signal) {
		for _, s := range sigs {
			candidates[s.Need] = append(candidates[s.Need], s)
		}
	}

	walkErr := filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries; keep scanning the rest
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if path != repoPath && skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(repoPath, path)
		if relErr != nil {
			return nil
		}
		analyzeFile(path, filepath.ToSlash(rel), d, add)
		return nil
	})
	if walkErr != nil {
		return Plan{}, fmt.Errorf("infrascan: scan repo: %w", walkErr)
	}

	return finalize(candidates), nil
}

// finalize turns the raw per-need candidates into a Plan: set a flag when it has
// any candidate, apply the Supabase-supersedes-Postgres rule, then emit Signals
// only for needs that ended up true.
func finalize(candidates map[Need][]Signal) Plan {
	p := Plan{
		Supabase:      len(candidates[NeedSupabase]) > 0,
		Postgres:      len(candidates[NeedPostgres]) > 0,
		Redis:         len(candidates[NeedRedis]) > 0,
		Queue:         len(candidates[NeedQueue]) > 0,
		ObjectStorage: len(candidates[NeedObjectStorage]) > 0,
	}

	// Supabase brings its own Postgres, so a Supabase app does not also need a
	// shared-cluster Postgres database — even if a bare postgres:// URL is
	// present (that's the Supabase DB). Drop the Postgres need and its evidence.
	if p.Supabase {
		p.Postgres = false
		delete(candidates, NeedPostgres)
	}

	p.Signals = collectSignals(candidates, p)
	return p
}

// collectSignals flattens the candidates of true needs into a deduplicated,
// deterministically-ordered slice.
func collectSignals(candidates map[Need][]Signal, p Plan) []Signal {
	truthy := map[Need]bool{
		NeedSupabase:      p.Supabase,
		NeedPostgres:      p.Postgres,
		NeedRedis:         p.Redis,
		NeedQueue:         p.Queue,
		NeedObjectStorage: p.ObjectStorage,
	}
	seen := map[Signal]bool{}
	var out []Signal
	for need, sigs := range candidates {
		if !truthy[need] {
			continue
		}
		for _, s := range sigs {
			if seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Need != out[j].Need {
			return out[i].Need < out[j].Need
		}
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Pattern < out[j].Pattern
	})
	return out
}

// skipDirs are directories that hold dependencies or build artifacts, not the
// app's own manifests/source — scanning them would be slow and produce false
// positives (e.g. a transitive dep's package.json).
var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, "vendor": true, "dist": true,
	"build": true, "out": true, ".next": true, ".nuxt": true,
	".svelte-kit": true, "target": true, ".venv": true, "venv": true,
	"__pycache__": true, ".terraform": true, "coverage": true,
}

func skipDir(name string) bool { return skipDirs[name] }

// readCapped reads path only if it is at most max bytes, so a pathological file
// can't blow up memory. The bool reports whether content was read.
func readCapped(path string, max int64) ([]byte, bool) {
	info, err := os.Stat(path)
	if err != nil || info.Size() > max {
		return nil, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return b, true
}
