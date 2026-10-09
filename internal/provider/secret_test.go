package provider

import (
	"reflect"
	"testing"

	"github.com/Groupe-Hevea/terraform-provider-lastpass/internal/lastpass"
)

func TestFullnameRoundTrip(t *testing.T) {
	for _, test := range []struct {
		fullname           string
		share, group, name string
	}{
		{"entry", "", "", "entry"},
		{"folder/entry", "", "folder", "entry"},
		{"folder/sub/entry", "", "folder/sub", "entry"},
		{"Shared-Infra/entry", "Shared-Infra", "", "entry"},
		{"Shared-Infra/tfstates/aws_iam_key", "Shared-Infra", "tfstates", "aws_iam_key"},
		{"Shared-Infra/Github/Deploy_keys/repo for app", "Shared-Infra", "Github/Deploy_keys", "repo for app"},
		// Without a "/", a name that merely looks like a shared folder is a name.
		{"Shared-Infra", "", "", "Shared-Infra"},
	} {
		share, group, name := splitFullname(test.fullname)
		if share != test.share || group != test.group || name != test.name {
			t.Errorf("splitFullname(%q) = (%q, %q, %q), want (%q, %q, %q)",
				test.fullname, share, group, name, test.share, test.group, test.name)
		}
		if got := fullname(&lastpass.Account{Share: share, Group: group, Name: name}); got != test.fullname {
			t.Errorf("fullname of the parts of %q = %q", test.fullname, got)
		}
	}
}

func TestNoteConvention(t *testing.T) {
	for _, test := range []struct {
		configured, stored, exposed string
	}{
		{"", "", ""},
		{"one line", "one line", "one line"},
		{"heredoc line\n", "heredoc line", "heredoc line"},
		{"first\nsecond\n", "first\nsecond", "first\nsecond\n"},
		{"first\nsecond", "first\nsecond", "first\nsecond\n"},
	} {
		if got := storedNote(test.configured); got != test.stored {
			t.Errorf("storedNote(%q) = %q, want %q", test.configured, got, test.stored)
		}
		if got := exposedNote(test.stored); got != test.exposed {
			t.Errorf("exposedNote(%q) = %q, want %q", test.stored, got, test.exposed)
		}
		if !sameNote(test.configured, test.stored) {
			t.Errorf("sameNote(%q, %q) = false", test.configured, test.stored)
		}
	}
	if sameNote("a\nb", "a\nc") {
		t.Error("different notes reported as the same")
	}
}

func TestCustomFields(t *testing.T) {
	note := "NoteType:SSH Key\nLanguage:en-US\nPassphrase:p:with:colons\nPublic Key:ssh-ed25519 AAAA\nNotes:first line\nsecond line\n"
	want := map[string]string{
		"NoteType":   "SSH Key",
		"Language":   "en-US",
		"Passphrase": "p:with:colons",
		"Public Key": "ssh-ed25519 AAAA",
		"Notes":      "first line\nsecond line\n",
	}
	if got := customFields(note); !reflect.DeepEqual(got, want) {
		t.Errorf("customFields = %#v, want %#v", got, want)
	}
	if got := customFields("just a note\nKey:Value"); len(got) != 0 {
		t.Errorf("an untyped note produced fields: %#v", got)
	}
}
