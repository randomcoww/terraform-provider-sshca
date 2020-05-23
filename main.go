package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/plugin"
	"github.com/randomcoww/terraform-provider-sshca/sshca"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: sshca.Provider})
}
