# lastpass_secret Resource

## Example Usage

```hcl
resource "lastpass_secret" "mysecret" {
  name     = "Shared-Infra/sites/My site"
  username = "foobar"
  password = file("${path.module}/secret")
  url      = "https://example.com"
  note     = <<-EOF
    Managed by Terraform.
    Do not edit by hand.
  EOF
}
```

## Argument Reference

* `name` - (Required) Full path of the entry: `<shared folder>/<folder>/<name>`, the first two being optional. A shared folder is recognised by its `Shared-` prefix and must already exist and be writable for the account. The folder may contain `/`. Changing the name recreates the entry.
* `username` - (Optional)
* `password` - (Optional)
* `url` - (Optional)
* `note` - (Optional) The provider stores the note without trailing newlines: a note that differs from the stored one only by trailing newlines is not a change.

An optional argument that is left out, or set to an empty string, keeps the value the entry already has.

## Existing entries

LastPass accepts several entries with the same name. If an entry already has the `name` being created, the resource adopts it: the entry is updated with the configured arguments, keeps the others, and is managed from then on. A warning says so. This also makes it safe to run `apply` again after a creation that failed half-way.

If several entries already share that name, the creation fails and lists their IDs: delete the extra ones, or import the right one.

## Attribute Reference

* `id` - Identifier assigned by LastPass.
* `fullname` - Same as `name`.
* `group` - Folder of the entry inside its shared folder.
* `last_modified_gmt` - Last modification, in seconds since the epoch.
* `last_touch` - Last access, in seconds since the epoch.

## Importer

Import a pre-existing secret in LastPass. Example:

```
terraform import lastpass_secret.mysecret 4252909269944373577
```

The ID needs to be a unique numerical value.
