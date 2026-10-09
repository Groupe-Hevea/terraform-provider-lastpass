package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/Groupe-Hevea/terraform-provider-lastpass/internal/provider"
)

// version is set by goreleaser.
var version = "dev"

func main() {
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/Groupe-Hevea/lastpass",
	})
	if err != nil {
		log.Fatal(err)
	}
}
