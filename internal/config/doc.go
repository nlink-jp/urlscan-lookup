// Package config resolves runtime settings from a sectioned-TOML file,
// environment variables, and flags, with precedence flag > env > config >
// default. The urlscan API key is a secret: it is read canonically from the
// URLSCAN_API_KEY environment variable (writing it in plaintext TOML is
// accepted for local convenience but discouraged), and is never logged.
package config
