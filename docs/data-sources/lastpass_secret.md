# lastpass_secret Data Source

## Example Usage

```hcl
data "lastpass_secret" "mydb" {
  id = "3863267983730403838"
}

resource "aws_db_instance" "mydb" {
  allocated_storage = 10
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  username          = data.lastpass_secret.mydb.username
  password          = data.lastpass_secret.mydb.password
}

# typed secure note (server, SSH key, ...)
output "host" {
  value     = data.lastpass_secret.mydb.custom_fields["Hostname"]
  sensitive = true
}
```

## Argument Reference

* `id` - (Required) Must be unique numerical value. An ID that does not exist is an error.

## Attribute Reference

* `name` - Full path of the entry: `<shared folder>/<folder>/<name>`.
* `fullname` - Same as `name`.
* `username`
* `password`
* `last_modified_gmt`
* `last_touch`
* `group`
* `url`
* `note` - A multi-line note is returned with a final newline.
* `custom_fields` - Fields of a typed secure note, by name. Empty for other entries.
