package provider

import (
	"strings"

	"github.com/Groupe-Hevea/terraform-provider-lastpass/internal/lastpass"
)

// sharedFolderPrefix is how LastPass names every shared folder.
const sharedFolderPrefix = "Shared-"

// fullname is the path of an entry as Terraform configurations write it:
// "<shared folder>/<folder>/<name>", the first two being optional.
func fullname(account *lastpass.Account) string {
	var parts []string
	for _, part := range []string{account.Share, account.Group, account.Name} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, "/")
}

// splitFullname is the inverse of fullname. The name is what follows the last
// "/"; a leading "Shared-..." segment is the shared folder; what remains in
// between is the folder, which may itself contain "/".
func splitFullname(fullname string) (share, group, name string) {
	rest := fullname
	if strings.HasPrefix(rest, sharedFolderPrefix) {
		if first, after, found := strings.Cut(rest, "/"); found {
			share, rest = first, after
		}
	}
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		return share, rest[:i], rest[i+1:]
	}
	return share, "", rest
}

// LastPass entries written by this provider's predecessor, which went through
// the lpass command line client, hold their note without trailing newline,
// while configurations usually write notes as heredocs, which end with one.
// The three functions below keep that convention so existing states and
// configurations match without rewriting any entry.

// storedNote is the note as it is saved in LastPass.
func storedNote(note string) string {
	return strings.TrimRight(note, "\n")
}

// exposedNote is the note as Terraform sees it when nothing else is known:
// a multi-line note gets its final newline back.
func exposedNote(stored string) string {
	if strings.Contains(stored, "\n") {
		return stored + "\n"
	}
	return stored
}

// sameNote tells whether two notes differ at most by trailing newlines.
func sameNote(a, b string) bool {
	return storedNote(a) == storedNote(b)
}

// customFields extracts the fields of a typed secure note, whose note is a
// list of "Key:Value" lines starting with "NoteType:". The free-text field
// "Notes" comes last and may span several lines.
func customFields(note string) map[string]string {
	fields := map[string]string{}
	if !strings.HasPrefix(note, "NoteType:") {
		return fields
	}
	for _, line := range strings.Split(note, "\n") {
		key, value, found := strings.Cut(line, ":")
		if key == "Notes" {
			break
		}
		if found {
			fields[key] = value
		}
	}
	if _, text, found := strings.Cut(note, "\nNotes:"); found {
		fields["Notes"] = text
	}
	return fields
}
