# terraform-provider-lastpass

Terraform provider to read, manage and destroy entries of a LastPass vault.

It talks to LastPass directly, without the `lpass` command line client. LastPass has no public API for vault entries: the provider speaks the private protocol of the official client, implemented in `internal/lastpass`.

```hcl
terraform {
  required_providers {
    lastpass = {
      source = "Groupe-Hevea/lastpass"
    }
  }
}

resource "lastpass_secret" "mysecret" {
  name     = "Shared-Infra/sites/My site"
  username = "foobar"
  password = file("${path.module}/secret")
  url      = "https://example.com"
}
```

Documentation: [docs](docs/index.md).

## Development

Tools are pinned with [aqua](https://aquaproj.github.io/) (`aqua i`), tasks run with [Task](https://taskfile.dev/):

```
task test      # go vet, unit tests, and Terraform runs against a fake LastPass server
task install   # build the provider into $GOBIN, for a dev override
```

The tests never reach LastPass: `internal/lastpass/lastpasstest` is an in-memory server that speaks the real wire formats, with its own cryptography.

A release is cut by pushing a `v*` tag.

## Origins

Fork of [nrkno/terraform-provider-lastpass](https://github.com/nrkno/terraform-provider-lastpass), rewritten in version 1 on the Terraform plugin framework. The LastPass client derives from [ansd/lastpass-go](https://github.com/ansd/lastpass-go) (MIT, see `internal/lastpass/LICENSE`) through its fork [veloceapps/lastpass-go](https://github.com/veloceapps/lastpass-go).

## License

[Apache](LICENSE)
