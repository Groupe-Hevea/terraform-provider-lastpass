# LastPass Provider

The LastPass provider reads, manages and destroys entries of a LastPass vault.

It talks to LastPass directly: no `lpass` binary is needed. LastPass has no public API for vault entries, so the provider speaks the same private protocol as the official command line client.

-> Set the `LASTPASS_USER` and `LASTPASS_PASSWORD` environment variables to keep the login out of your .tf files.

~> Accounts that require a second factor are not supported: use a dedicated service account.

The provider logs in only when a resource or data source needs it. LastPass can only serve the vault whole: it is downloaded once for all the reads of a run, and once more after each write.

## Example Usage

```hcl
resource "random_password" "pw" {
  length  = 32
  special = false
}

resource "lastpass_secret" "mylogin" {
  name     = "Shared-Infra/services/My service"
  username = "foobar"
  password = random_password.pw.result
}
```

## Argument Reference

* `username` - (Optional) LastPass login e-mail. Defaults to the `LASTPASS_USER` environment variable.
* `password` - (Optional) LastPass master password. Defaults to the `LASTPASS_PASSWORD` environment variable.

Both are required as soon as a resource or data source is used, and must be known at plan time.

## Upgrading from 0.x

Version 1 keeps the schema of `lastpass_secret` (resource and data source): existing states are read as they are, and Terraform 1.0 or later is required. What changes:

* the `lpass` binary is no longer used, nor is an existing `lpass` session;
* creating an entry whose name is already taken adopts the existing entry, with a warning, instead of adding a second entry with the same name;
* a data source whose `id` does not exist is now an error, instead of silently returning empty values;
* notes and custom fields containing non-ASCII characters are now read correctly (`lpass` corrupted them in its JSON output);
* values are written as configured: `lpass` trimmed surrounding whitespace from every field and prefixed `http://` to a URL without scheme, including an empty one. Only the trailing newlines of a note are still removed;
* the name of a shared folder must match its case exactly;
* a name that LastPass would store under another path (leading, trailing or doubled `/`) is rejected at plan time.
