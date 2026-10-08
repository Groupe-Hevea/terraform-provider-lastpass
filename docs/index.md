# Lastpass Provider

The Lastpass provider reads, manages and destroys entries of a LastPass vault.

It talks to LastPass directly: no `lpass` binary is needed. LastPass has no public API for vault entries, so the provider speaks the same private protocol as the official command line client.

-> Set the `LASTPASS_USER` and `LASTPASS_PASSWORD` environment variables to keep the login out of your .tf files.

~> Accounts that require a second factor are not supported: use a dedicated service account.

The provider logs in only when a resource or data source needs it, and downloads the vault once per Terraform run.

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

Both are required as soon as a resource or data source is used.

## Upgrading from 0.x

Version 1 keeps the schema of `lastpass_secret` (resource and data source): existing states are read as they are. What changes:

* the `lpass` binary is no longer used, nor is an existing `lpass` session;
* a data source whose `id` does not exist is now an error, instead of silently returning empty values;
* notes and custom fields containing non-ASCII characters are now read correctly (`lpass` corrupted them in its JSON output).
