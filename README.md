# infrascan

Scan a checked-out repository and report which infrastructure primitives the
application actually uses, with the evidence for every answer.

```go
plan, err := infrascan.Detect(ctx, "/path/to/checkout")
// plan.Postgres  -> true
// plan.Redis     -> true
// plan.Supabase  -> false
// plan.Signals   -> [{Need: "postgres", File: "go.mod", Pattern: "jackc/pgx"}, ...]
```

`Detect` is pure. It reads files under the path it is given and does nothing
else: no network, no database, no deploys. What you do with a `Plan` is your
problem.

## Why

Platforms provision infrastructure for applications, and the easy way to do
that is to give every tenant everything. A Postgres, a Redis, a queue, an
object store, a Supabase stack. It works on the first day and the bill grows
for the rest of the year, because most applications use two of those five and
nobody goes back to check which.

This library is the check. Point it at the repository and it tells you what the
code imports, so you provision that and nothing else.

## Explainability is the point

Every capability flag set to `true` carries at least one `Signal` naming the
file and the exact token that triggered it:

```json
{ "need": "redis", "file": "package.json", "pattern": "ioredis" }
```

A provisioning decision that cannot be explained will eventually be overridden
by someone who does not trust it. Signals exist so the answer survives the
argument.

## Needs detected

| Need | Signals from |
|---|---|
| `supabase` | `@supabase/supabase-js`, Supabase env vars, client construction in JS sources |
| `postgres` | `pg`, `pg-promise`, `postgres` (postgres.js), `jackc/pgx`, `lib/pq`, Prisma `postgresql` provider, `DATABASE_URL` |
| `redis` | `ioredis`, `redis`, `iovalkey`, `@valkey/valkey-glide`, Go redis clients |
| `queue` | `amqplib`, `amqp`, `amqp-connection-manager`, Go AMQP clients |
| `object_storage` | `@aws-sdk/client-s3`, `aws-sdk`, `minio`, Go S3 and MinIO SDKs |

Supabase supersedes Postgres. A Supabase project exposes its own Postgres, so a
repository using Supabase must not also be given a database from the shared
cluster, even though its `DATABASE_URL` looks exactly like one that would.

## What it reads

Direct-dependency manifests only: `package.json`, `go.mod`, `requirements.txt`,
`Pipfile`, `pyproject.toml`, `setup.py`, `schema.prisma`, `.env` files, and
JavaScript and TypeScript sources.

Lock files are deliberately skipped. `package-lock.json` and `poetry.lock`
carry the fully resolved transitive tree, so scanning them reports every
database driver that any dependency of any dependency happens to pull in. That
is how a static site ends up provisioned with a Postgres.

Matching is per-ecosystem rather than uniform. npm package names are matched
exactly, because `pg` and `redis` are too short to substring safely. Go module
paths are matched on fragments, because they are long and specific enough that
a substring cannot collide by accident. Reads are byte-capped, and the usual
build and vendor directories are skipped.

## Install

```
go get github.com/nmogbuk/infrascan
```

Go 1.24 or newer. No dependencies outside the standard library.

## Tests

```
go test ./...
```

Fixtures under `testdata/` cover a Supabase app, a plain Postgres Go service, a
Redis and S3 worker, and a static site that must detect nothing at all. The
last one is the important one.

## Licence

MIT.
