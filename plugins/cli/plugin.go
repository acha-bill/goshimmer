package cli

import (
	"fmt"
	"os"

	"github.com/iotaledger/hive.go/events"
	"github.com/iotaledger/hive.go/node"
	flag "github.com/spf13/pflag"

	"github.com/iotaledger/goshimmer/plugins/banner"
)

// PluginName is the name of the CLI plugin.
const PluginName = "CLI"

var (
	// plugin is the plugin instance of the CLI plugin.
	plugin  = node.NewPlugin(PluginName, node.Enabled)
	version = flag.BoolP("version", "v", false, "Prints the GoShimmer version")
)

// gets the plugin instance
func Plugin() *node.Plugin {
	return plugin
}

func init() {
	for name, plugin := range node.GetPlugins() {
		onAddPlugin(name, plugin.Status)
	}

	node.Events.AddPlugin.Attach(events.NewClosure(onAddPlugin))

	flag.Usage = printUsage

	plugin.Events.Init.Attach(events.NewClosure(onInit))
}

func onAddPlugin(name string, status int) {
	AddPluginStatus(node.GetPluginIdentifier(name), status)
}

func onInit(*node.Plugin) {
	if *version {
		fmt.Println(banner.AppName + " " + banner.AppVersion)
		os.Exit(0)
	}
}
