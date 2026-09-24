/**
 * PLATFORM-MANAGED FILE — DO NOT EDIT OR DELETE.
 * The platform overwrites this file on every run; local changes are lost.
 *
 * SQLite database shared by all server code. Import it from server code as:
 *   import { db, migrate } from './lib/db.js';   // from server/index.ts
 *
 * - `db` is a node:sqlite DatabaseSync — synchronous, no await needed:
 *     db.prepare('SELECT * FROM products WHERE id = ?').get(id)
 *     db.prepare('INSERT INTO orders (item, qty) VALUES (?, ?)').run(item, qty)
 *     db.prepare('SELECT * FROM products').all()
 * - Call `migrate(sql)` ONCE at server startup with idempotent
 *   `CREATE TABLE IF NOT EXISTS ...` statements.
 * - ALWAYS use parameterized queries (the ? placeholders) — never build SQL
 *   strings from user input.
 */
import { DatabaseSync } from 'node:sqlite';
import * as fs from 'node:fs';
import * as path from 'node:path';

// server/data/ is the ONLY directory that survives republishes — the
// platform mounts persistent storage there in production.
const DATA_DIR = path.join(process.cwd(), 'server', 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

export const db = new DatabaseSync(path.join(DATA_DIR, 'app.db'));

// WAL + busy timeout: concurrent requests queue instead of failing with
// SQLITE_BUSY, and a crash mid-write can't corrupt the database.
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA busy_timeout = 5000;');
db.exec('PRAGMA foreign_keys = ON;');

/**
 * Run idempotent schema statements (CREATE TABLE IF NOT EXISTS ...) once at
 * startup. On a fresh deployment this creates the schema in an empty
 * database; on a redeploy it is a no-op against existing data.
 */
export function migrate(schemaSql: string): void {
  db.exec(schemaSql);
}
