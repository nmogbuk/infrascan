package infrascan

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func flagsOf(p Plan) map[Need]bool {
	return map[Need]bool{
		NeedSupabase:      p.Supabase,
		NeedPostgres:      p.Postgres,
		NeedRedis:         p.Redis,
		NeedQueue:         p.Queue,
		NeedObjectStorage: p.ObjectStorage,
	}
}

// assertConsistent enforces the explainability invariant: every signal points at
// a need that is true and carries file+pattern evidence, and every true need has
// at least one signal.
func assertConsistent(t *testing.T, p Plan) {
	t.Helper()
	fl := flagsOf(p)
	seen := map[Need]bool{}
	for _, s := range p.Signals {
		if s.File == "" || s.Pattern == "" {
			t.Errorf("signal %+v is missing file/pattern evidence", s)
		}
		if !fl[s.Need] {
			t.Errorf("signal for need %q but its flag is false", s.Need)
		}
		seen[s.Need] = true
	}
	for need, on := range fl {
		if on && !seen[need] {
			t.Errorf("need %q is true but has no signal", need)
		}
	}
}

func TestDetect(t *testing.T) {
	cases := []struct {
		name string
		dir  string
		want map[Need]bool
	}{
		{
			name: "supabase js app -> Supabase only (Postgres superseded despite a postgres:// DATABASE_URL)",
			dir:  "testdata/supabase-js",
			want: map[Need]bool{NeedSupabase: true},
		},
		{
			name: "plain postgres go app -> Postgres only, never Supabase",
			dir:  "testdata/plain-postgres-go",
			want: map[Need]bool{NeedPostgres: true},
		},
		{
			name: "redis + s3 worker -> Redis and ObjectStorage",
			dir:  "testdata/redis-s3",
			want: map[Need]bool{NeedRedis: true, NeedObjectStorage: true},
		},
		{
			name: "static site -> empty plan",
			dir:  "testdata/static-site",
			want: map[Need]bool{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Detect(context.Background(), tc.dir)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			for need, on := range flagsOf(got) {
				if on != tc.want[need] {
					t.Errorf("need %q = %v, want %v (full plan: %+v)", need, on, tc.want[need], got)
				}
			}
			assertConsistent(t, got)
		})
	}
}

// TestDetect_SupabaseFixtureSuppressesPostgres pins the AC: the @supabase fixture
// reports Supabase with evidence, and Postgres stays false with no Postgres
// signal even though its .env.example carries a postgres:// DATABASE_URL.
func TestDetect_SupabaseFixtureSuppressesPostgres(t *testing.T) {
	got, err := Detect(context.Background(), "testdata/supabase-js")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !got.Supabase {
		t.Fatal("want Supabase true")
	}
	if got.Postgres {
		t.Error("want Postgres false (Supabase brings its own)")
	}
	var sawSupabaseEvidence bool
	for _, s := range got.Signals {
		if s.Need == NeedPostgres {
			t.Errorf("Postgres signal should be suppressed, got %+v", s)
		}
		if s.Need == NeedSupabase && s.File != "" && s.Pattern != "" {
			sawSupabaseEvidence = true
		}
	}
	if !sawSupabaseEvidence {
		t.Error("want a Supabase signal with file+pattern evidence")
	}
}

// TestFinalize_SupabaseSupersedesPostgres exercises the supersede rule directly,
// independent of any fixture file.
func TestFinalize_SupabaseSupersedesPostgres(t *testing.T) {
	cand := map[Need][]Signal{
		NeedSupabase: {{Need: NeedSupabase, File: "package.json", Pattern: "@supabase/supabase-js"}},
		NeedPostgres: {{Need: NeedPostgres, File: ".env.example", Pattern: "DATABASE_URL=postgres://"}},
	}
	p := finalize(cand)
	if !p.Supabase {
		t.Error("want Supabase true")
	}
	if p.Postgres {
		t.Error("want Postgres false (superseded)")
	}
	for _, s := range p.Signals {
		if s.Need == NeedPostgres {
			t.Errorf("Postgres signal should be dropped when superseded, got %+v", s)
		}
	}
}

func TestAnalyzers(t *testing.T) {
	cases := []struct {
		name      string
		fn        func(string, []byte) []Signal
		rel       string
		content   string
		wantNeeds []Need
		notNeeds  []Need
	}{
		{"npm pg", analyzePackageJSON, "package.json", `{"dependencies":{"pg":"^8.11.0"}}`, []Need{NeedPostgres}, []Need{NeedSupabase}},
		{"npm supabase", analyzePackageJSON, "package.json", `{"dependencies":{"@supabase/supabase-js":"^2"}}`, []Need{NeedSupabase}, nil},
		{"npm redis + s3", analyzePackageJSON, "package.json", `{"dependencies":{"ioredis":"^5","aws-sdk":"^2"}}`, []Need{NeedRedis, NeedObjectStorage}, nil},
		{"npm devDeps + amqp", analyzePackageJSON, "package.json", `{"devDependencies":{"amqplib":"^0.10"}}`, []Need{NeedQueue}, nil},
		{"npm exact-match: pg-boss is not pg", analyzePackageJSON, "package.json", `{"dependencies":{"pg-boss":"^9"}}`, nil, []Need{NeedPostgres}},
		{"gomod pgx", analyzeGoMod, "go.mod", "require github.com/jackc/pgx/v5 v5.7.2", []Need{NeedPostgres}, []Need{NeedSupabase}},
		{"gomod lib/pq + go-redis", analyzeGoMod, "go.mod", "require (\n\tgithub.com/lib/pq v1.10.9\n\tgithub.com/redis/go-redis/v9 v9.7.0\n)", []Need{NeedPostgres, NeedRedis}, nil},
		{"gomod minio + amqp091", analyzeGoMod, "go.mod", "require (\n\tgithub.com/minio/minio-go/v7 v7.0\n\tgithub.com/rabbitmq/amqp091-go v1.9\n)", []Need{NeedObjectStorage, NeedQueue}, nil},
		{"gomod valkey", analyzeGoMod, "go.mod", "require github.com/valkey-io/valkey-go v1.0.0", []Need{NeedRedis}, nil},
		{"gomod skips // indirect transitive deps", analyzeGoMod, "go.mod", "require (\n\tgithub.com/jackc/pgx/v5 v5.7.2\n\tgithub.com/redis/go-redis/v9 v9.7.0 // indirect\n)", []Need{NeedPostgres}, []Need{NeedRedis}},
		{"npm valkey (iovalkey)", analyzePackageJSON, "package.json", `{"dependencies":{"iovalkey":"^0.1.0"}}`, []Need{NeedRedis}, nil},
		{"npm amqp package", analyzePackageJSON, "package.json", `{"dependencies":{"amqp":"^0.2.4"}}`, []Need{NeedQueue}, nil},
		{"py valkey", analyzePythonManifest, "requirements.txt", "valkey==6.0.0\n", []Need{NeedRedis}, nil},
		{"py amqp", analyzePythonManifest, "requirements.txt", "amqp==5.1.1\n", []Need{NeedQueue}, nil},
		{"py psycopg + boto3", analyzePythonManifest, "requirements.txt", "psycopg2-binary==2.9.9\nboto3==1.34.0\n", []Need{NeedPostgres, NeedObjectStorage}, nil},
		{"py pika", analyzePythonManifest, "requirements.txt", "pika==1.3.2\n", []Need{NeedQueue}, nil},
		{"py supabase", analyzePythonManifest, "requirements.txt", "supabase==2.4.0\n", []Need{NeedSupabase}, nil},
		{"prisma postgres", analyzePrismaSchema, "prisma/schema.prisma", "datasource db {\n  provider = \"postgresql\"\n}", []Need{NeedPostgres}, nil},
		{"prisma mysql is not postgres", analyzePrismaSchema, "prisma/schema.prisma", "datasource db {\n  provider = \"mysql\"\n}", nil, []Need{NeedPostgres}},
		{"env DATABASE_URL postgres", analyzeEnvFile, ".env.example", "DATABASE_URL=postgres://u:p@h:5432/db\n", []Need{NeedPostgres}, []Need{NeedSupabase}},
		{"env DATABASE_URL postgresql scheme", analyzeEnvFile, ".env", "DATABASE_URL=postgresql://u:p@h/db\n", []Need{NeedPostgres}, nil},
		{"env DATABASE_URL mysql is not postgres", analyzeEnvFile, ".env.example", "DATABASE_URL=mysql://u:p@h/db\n", nil, []Need{NeedPostgres}},
		{"js supabase createClient", analyzeJSSource, "src/client.js", "import { createClient } from '@supabase/supabase-js'\nexport const s = createClient(a, b)", []Need{NeedSupabase}, nil},
		{"js createClient without supabase import", analyzeJSSource, "src/other.js", "const c = createClient({ host: 'x' })", nil, []Need{NeedSupabase}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.fn(tc.rel, []byte(tc.content))
			present := map[Need]bool{}
			for _, s := range got {
				present[s.Need] = true
				if s.File != tc.rel || s.Pattern == "" {
					t.Errorf("signal %+v has wrong file or empty pattern (rel=%q)", s, tc.rel)
				}
			}
			for _, n := range tc.wantNeeds {
				if !present[n] {
					t.Errorf("want need %q present, got signals %+v", n, got)
				}
			}
			for _, n := range tc.notNeeds {
				if present[n] {
					t.Errorf("did not want need %q, got signals %+v", n, got)
				}
			}
		})
	}
}

// TestDetect_ReadOnly proves Detect performs no DB writes / no side effects (the
// AC) — it runs against a temp dir with no DB or network configured, and the dir
// is byte-for-byte identical before and after.
func TestDetect_ReadOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module x\n\nrequire github.com/jackc/pgx/v5 v5.7.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	before := snapshot(t, dir)
	p, err := Detect(context.Background(), dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !p.Postgres {
		t.Error("expected Postgres from a pgx dependency")
	}
	after := snapshot(t, dir)
	if !reflect.DeepEqual(before, after) {
		t.Errorf("Detect mutated the repo dir.\nbefore=%v\nafter=%v", before, after)
	}
}

func TestDetect_NotADirectory(t *testing.T) {
	if _, err := Detect(context.Background(), filepath.Join("testdata", "static-site", "index.html")); err == nil {
		t.Error("expected an error when repoPath is not a directory")
	}
}

// TestDetect_IgnoresLockFiles proves transitive deps in lock files don't leak
// into the Plan: a poetry.lock that mentions redis must not flag Redis; only the
// direct requirements.txt counts.
func TestDetect_IgnoresLockFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("psycopg2-binary==2.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "poetry.lock"),
		[]byte("[[package]]\nname = \"redis\"\nversion = \"5.0.1\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Detect(context.Background(), dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !got.Postgres {
		t.Error("want Postgres from the direct requirements.txt")
	}
	if got.Redis {
		t.Error("Redis must NOT be flagged from a transitive dep in poetry.lock")
	}
}

type fileStat struct {
	size    int64
	modNano int64
}

// snapshot records every file's size+modtime under dir, so any write Detect made
// would change the result.
func snapshot(t *testing.T, dir string) map[string]fileStat {
	t.Helper()
	out := map[string]fileStat{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		out[rel] = fileStat{size: info.Size(), modNano: info.ModTime().UnixNano()}
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return out
}
