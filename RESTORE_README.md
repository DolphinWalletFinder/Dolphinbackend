# JSON Backup Auto-Restore (Railway-friendly)

On startup, the server will restore the SQLite database from `db_backup.json` if the DB file does not exist,
or if `FORCE_RESTORE=true` is set in environment variables.

## Environment variables
- `DATABASE_PATH`: Path to the SQLite file (e.g. `/data/app.db`). If your code already sets this, keep it.
- `BACKUP_JSON_PATH` (optional): Absolute/relative path to your JSON backup file. Defaults to `./db_backup.json`.
- `FORCE_RESTORE` (optional): Set to `true` to overwrite the database from JSON on each start (use cautiously).

## Notes
- All inserts are performed within a transaction and use `INSERT OR REPLACE` to preserve explicit IDs.
- Only tables present in the JSON and existing in SQLite are affected.
- Passwords in `users` should be hashed already if you plan to sign in with them.