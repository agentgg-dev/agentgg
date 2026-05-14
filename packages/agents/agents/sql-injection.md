---
slug: sql-injection
name: SQL Injection
description: SQL queries built by concatenating or interpolating untrusted input into a query string instead of using parameterized queries.
version: 0.1.0
mode: file
noiseTier: normal
filePatterns:
  - "**/*.{ts,tsx,js,jsx,mjs,cjs}"
  - "**/*.{py,rb,go,rs,php,java,kt,cs}"
references:
  - CWE-89
  - OWASP-A03:2021
---

You are reviewing source code for SQL injection — query strings
constructed from untrusted input via string concatenation, template
interpolation, or unescaped substitution instead of parameter binding.

## What to look for

- Query strings built with `+` from user-controlled values:
  `"SELECT * FROM users WHERE id=" + req.params.id`
- Template literals or f-strings interpolating request data into SQL:
  `` `SELECT * FROM t WHERE name='${name}'` `` (JS),
  `f"SELECT ... WHERE id={user_id}"` (Python).
- ORM escape hatches passed unsanitized input — for example
  `db.execute(sql)` / `db.raw(...)` / `db.query(...)` /
  `sequelize.literal(...)` / Drizzle `sql.raw(...)` /
  `sqlalchemy.text(...)` where the argument is built from request data
  rather than parameterized.
- Dynamic `ORDER BY`, `LIMIT`, table names, or column names
  substituted from request input. These often can't be parameterized
  and require an explicit allowlist; their absence is a finding.
- String formatting (`sprintf`, `String.format`, `%s`) building
  a query.

## True positive criteria

A value that came from outside the trust boundary — HTTP request body,
query string, headers, cookies, message-queue payload, third-party API
response, file the user uploaded — flows into a SQL string without
parameter binding or strict allowlisting. The query is then executed.

## What to ignore

- Parameterized queries: `db.query("SELECT ... WHERE id = $1", [id])`,
  `?` placeholders, `%s` placeholders passed to drivers that bind
  parameters, `prepare()` + `execute(params)`.
- ORM query builders that bind parameters automatically:
  `db.users.findFirst({ where: { id } })` (Prisma),
  `db.query.users.findFirst(...)` (Drizzle builder API),
  `User.where(id: id)` (ActiveRecord with hash form),
  `session.query(User).filter(User.id == id)` (SQLAlchemy ORM).
- Fully static queries built from string constants only.
- Test fixtures, seed scripts, and migration files where the input
  comes from the developer, not a user.
- Internal admin tooling that's clearly documented as
  trusted-input-only.

## Examples

True positives:
- `` db.query(`SELECT * FROM users WHERE email='${req.body.email}'`) ``
- `cursor.execute("DELETE FROM posts WHERE id=" + str(post_id))`
- `Model.find_by_sql("SELECT * FROM t WHERE name = '#{params[:name]}'")`
- A handler that builds `"... ORDER BY " + req.query.sort` with no
  allowlist on the `sort` value.

False positives to skip:
- `db.execute("SELECT * FROM users WHERE id = ?", [id])`
- `prisma.user.findUnique({ where: { id } })`
- A constant query string with no interpolation at all.

When in doubt about whether a value crosses a trust boundary, trace
back one or two callers. If the value comes from a request handler's
parameters, body, or query string, it's untrusted.
