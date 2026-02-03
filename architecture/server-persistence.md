# Server Persistence

## Overview

Navigator Server persists protobuf messages in a single `objects` table. The persistence layer is
implemented in `crates/navigator-server/src/persistence/` and is selected at runtime based on the
database URL scheme.

Supported backends:
- Postgres (`postgres://` or `postgresql://`)
- SQLite (`sqlite:`)

The server requires a database URL. The CLI enforces `--db-url` / `NAVIGATOR_DB_URL`, and
`run_server` will reject an empty value.

Example in-memory SQLite URL:
`sqlite::memory:?cache=shared`

## Data Model

Both Postgres and SQLite migrations create the same table:
- `object_type` (string)
- `id` (string)
- `payload` (binary protobuf bytes)
- `created_at_ms` (i64 ms since UNIX epoch)
- `updated_at_ms` (i64 ms since UNIX epoch)
- Primary key: (`object_type`, `id`)

Migrations live in:
- `crates/navigator-server/migrations/postgres/`
- `crates/navigator-server/migrations/sqlite/`

## Store Selection and Migrations

`Store::connect` inspects the database URL scheme and constructs `PostgresStore` or `SqliteStore`.
Each store runs its migrations on connect before serving requests.

SQLite uses a smaller connection pool (1) for in-memory databases and a default of 5 for file-backed
databases. Postgres defaults to 10 connections.

## CRUD Semantics

### Put

`Store::put` performs an upsert into `objects` and updates `updated_at_ms`. The `created_at_ms` value
is only set on first insert.

- Postgres: `INSERT ... ON CONFLICT (object_type, id) DO UPDATE ...`
- SQLite: `INSERT ... ON CONFLICT (object_type, id) DO UPDATE ...`

### Get / Delete

`Store::get` and `Store::delete` operate by primary key (`object_type`, `id`).

### List

`Store::list` pages by `limit` + `offset` and uses deterministic ordering:
`ORDER BY created_at_ms ASC, id ASC`. The secondary sort avoids unstable ordering when multiple rows
share the same millisecond timestamp.

## Protobuf Ergonomics

Typed protobuf persistence is exposed through:
- `Store::put_message<T: Message + ObjectType + ObjectId>`
- `Store::get_message<T: Message + Default + ObjectType>`

`ObjectType` provides the per-message object type string.
`ObjectId` returns the message id used as the primary key.

Example usage:

```rust
store.put_message(&object).await?;
let object = store.get_message::<MyType>("object-id").await?;
```
