// Package cache is a per-key TTL cache for urlscan result and search
// responses, so repeated lookups do not re-spend the low free-plan quota.
// Active scans are never cached (each submit generates a new scan). Freshness
// lives inside the record, not the file mtime, so it survives copies and
// backups; writes are atomic (temp file + rename).
package cache
