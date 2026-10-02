package infrascan

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
)

// analyzeFile dispatches a single file to the matcher for its kind and feeds any
// resulting candidate signals to add.
func analyzeFile(path, rel string, d fs.DirEntry, add func(...Signal)) {
	base := strings.ToLower(d.Name())
	switch {
	case base == "package.json":
		if b, ok := readCapped(path, maxManifestBytes); ok {
			add(analyzePackageJSON(rel, b)...)
		}
	case base == "go.mod":
		if b, ok := readCapped(path, maxManifestBytes); ok {
			add(analyzeGoMod(rel, b)...)
		}
	case base == "requirements.txt" || base == "pipfile" ||
		base == "pyproject.toml" || base == "setup.py":
		// Only direct-dependency manifests — NOT lock files (poetry.lock /
		// Pipfile.lock / package-lock.json), whose fully-resolved transitive
		// deps would produce false positives against the "conservative" rule.
		if b, ok := readCapped(path, maxManifestBytes); ok {
			add(analyzePythonManifest(rel, b)...)
		}
	case base == "schema.prisma":
		if b, ok := readCapped(path, maxManifestBytes); ok {
			add(analyzePrismaSchema(rel, b)...)
		}
	case base == ".env" || strings.HasPrefix(base, ".env."):
		if b, ok := readCapped(path, maxManifestBytes); ok {
			add(analyzeEnvFile(rel, b)...)
		}
	default:
		if isJSSource(base) {
			if b, ok := readCapped(path, maxSourceBytes); ok {
				add(analyzeJSSource(rel, b)...)
			}
		}
	}
}

// npmDeps maps an exact npm package name to the need it signals. Exact-match
// only — package names like "pg" are too short for safe substring matching.
var npmDeps = map[string]Need{
	"@supabase/supabase-js":   NeedSupabase,
	"pg":                      NeedPostgres,
	"pg-promise":              NeedPostgres,
	"postgres":                NeedPostgres, // postgres.js
	"ioredis":                 NeedRedis,
	"redis":                   NeedRedis,
	"iovalkey":                NeedRedis, // valkey (ioredis fork)
	"@valkey/valkey-glide":    NeedRedis,
	"amqplib":                 NeedQueue,
	"amqp":                    NeedQueue,
	"amqp-connection-manager": NeedQueue,
	"@aws-sdk/client-s3":      NeedObjectStorage,
	"aws-sdk":                 NeedObjectStorage,
	"minio":                   NeedObjectStorage,
}

// goModFragments are distinctive module-path fragments. go.mod paths are long
// and specific enough that substring matching is safe.
var goModFragments = []struct {
	frag string
	need Need
}{
	{"supabase", NeedSupabase},
	{"jackc/pgx", NeedPostgres},
	{"lib/pq", NeedPostgres},
	{"go-redis", NeedRedis},
	{"gomodule/redigo", NeedRedis},
	{"valkey", NeedRedis}, // valkey-io/valkey-go etc.
	{"amqp091", NeedQueue},
	{"streadway/amqp", NeedQueue},
	{"aws-sdk-go", NeedObjectStorage},
	{"minio-go", NeedObjectStorage},
}

// pyTokens are distinctive package tokens in Python manifests. These are
// specific enough for substring matching, mirroring the builder's detector.
var pyTokens = []struct {
	tok  string
	need Need
}{
	{"supabase", NeedSupabase},
	{"psycopg", NeedPostgres}, // psycopg, psycopg2, psycopg2-binary, psycopg[binary]
	{"asyncpg", NeedPostgres},
	{"redis", NeedRedis},
	{"valkey", NeedRedis},
	{"pika", NeedQueue},
	{"amqp", NeedQueue}, // the `amqp` py package (kombu/celery transport)
	{"boto3", NeedObjectStorage},
	{"minio", NeedObjectStorage},
}

// analyzePackageJSON matches Node dependencies against npmDeps by exact name.
func analyzePackageJSON(rel string, content []byte) []Signal {
	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(content, &pkg); err != nil {
		return nil
	}
	var sigs []Signal
	for _, deps := range []map[string]string{
		pkg.Dependencies, pkg.DevDependencies, pkg.PeerDependencies, pkg.OptionalDependencies,
	} {
		for name := range deps {
			if need, ok := npmDeps[name]; ok {
				sigs = append(sigs, Signal{Need: need, File: rel, Pattern: name})
			}
		}
	}
	return sigs
}

// analyzeGoMod matches go.mod against distinctive module-path fragments, line by
// line so `// indirect` (transitive) requirements are skipped — a transitive
// infra dependency doesn't mean the app itself uses that infra.
func analyzeGoMod(rel string, content []byte) []Signal {
	var sigs []Signal
	for _, line := range strings.Split(string(content), "\n") {
		if strings.Contains(line, "// indirect") {
			continue
		}
		lower := strings.ToLower(line)
		for _, f := range goModFragments {
			if strings.Contains(lower, f.frag) {
				sigs = append(sigs, Signal{Need: f.need, File: rel, Pattern: f.frag})
			}
		}
	}
	return sigs
}

// analyzePythonManifest matches Python manifests against distinctive tokens.
func analyzePythonManifest(rel string, content []byte) []Signal {
	lower := strings.ToLower(string(content))
	var sigs []Signal
	for _, t := range pyTokens {
		if strings.Contains(lower, t.tok) {
			sigs = append(sigs, Signal{Need: t.need, File: rel, Pattern: t.tok})
		}
	}
	return sigs
}

// prismaPostgres matches a Prisma datasource configured for Postgres. Prisma is
// DB-agnostic, so only the postgresql provider counts as a Postgres signal.
var prismaPostgres = regexp.MustCompile(`(?i)provider\s*=\s*["']postgresql["']`)

func analyzePrismaSchema(rel string, content []byte) []Signal {
	if prismaPostgres.Match(content) {
		return []Signal{{Need: NeedPostgres, File: rel, Pattern: `provider = "postgresql"`}}
	}
	return nil
}

// dbURLPostgres matches a DATABASE_URL set to a Postgres DSN in an env file. A
// bare postgres:// is plain Postgres, not Supabase (Supabase is detected only by
// its client SDK, and the finalize step supersedes Postgres when Supabase wins).
var dbURLPostgres = regexp.MustCompile(`(?im)^[ \t]*[a-z0-9_]*database_url[ \t]*=[ \t]*["']?\s*postgres(?:ql)?://`)

func analyzeEnvFile(rel string, content []byte) []Signal {
	if dbURLPostgres.Match(content) {
		return []Signal{{Need: NeedPostgres, File: rel, Pattern: "DATABASE_URL=postgres://"}}
	}
	return nil
}

// isJSSource reports whether a filename is JS/TS source (where a Supabase
// createClient init would appear).
func isJSSource(base string) bool {
	switch filepath.Ext(base) {
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
		return true
	}
	return false
}

// analyzeJSSource corroborates Supabase usage from source: a file that both
// imports @supabase/supabase-js and calls createClient(. This catches usage that
// a manifest scan would miss (e.g. a CDN/unpinned import).
func analyzeJSSource(rel string, content []byte) []Signal {
	s := string(content)
	if strings.Contains(s, "@supabase/supabase-js") && strings.Contains(s, "createClient(") {
		return []Signal{{Need: NeedSupabase, File: rel, Pattern: "createClient("}}
	}
	return nil
}
