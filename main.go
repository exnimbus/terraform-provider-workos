// Copyright (c) OSO DevOps
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/exnimbus/terraform-provider-workos/internal/client"
	"github.com/exnimbus/terraform-provider-workos/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

// Run "go generate" to format example terraform files and generate the docs for the registry/website

// If you do not have terraform installed, you can remove the formatting command, but its suggested to
// ensure the documentation is formatted properly.
//go:generate tofu fmt -recursive ./examples/

// Generate registry docs from an OpenTofu-exported provider schema.
//go:generate sh scripts/generate-docs.sh

var (
	// these will be set by the goreleaser configuration
	// to appropriate values for the compiled binary.
	version string = "dev"
)

func main() {
	if len(os.Args) == 2 {
		var err error
		switch os.Args[1] {
		case "login":
			err = client.MCPLogin(context.Background(), os.Stdout)
		case "status":
			err = client.MCPStatus(context.Background(), os.Stdout)
		case "logout":
			err = client.MCPLogout(os.Stdout)
		default:
			err = fmt.Errorf("unknown command %q; expected login, status, or logout", os.Args[1])
		}
		if err != nil {
			log.Fatal(err)
		}
		return
	}
	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		// This address is also used by OpenTofu development overrides.
		Address: "registry.opentofu.org/exnimbus/workos",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), provider.New(version), opts)

	if err != nil {
		log.Fatal(err.Error())
	}
}
