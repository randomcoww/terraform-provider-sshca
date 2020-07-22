package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/plugin"
	"github.com/randomcoww/terraform-provider-ssh/ssh"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: ssh.Provider})
}
