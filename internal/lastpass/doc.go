// Package lastpass is a minimal LastPass vault client: it logs in with a
// master password, downloads and decrypts the vault, and creates, updates and
// deletes entries, including entries in shared folders.
//
// LastPass has no public API for vault items. This client speaks the same
// private protocol as the official command line client (lastpass-cli), which
// is the reference whenever behaviour is unclear.
//
// It derives from github.com/ansd/lastpass-go (MIT, see LICENSE) through its
// fork github.com/veloceapps/lastpass-go, reduced to what the provider needs.
package lastpass
