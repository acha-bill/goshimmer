package config

import (
	"github.com/iotaledger/hive.go/logger"
	"github.com/iotaledger/hive.go/node"
	"github.com/iotaledger/hive.go/parameter"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	// flags
	configName    = flag.StringP("config", "c", "config", "Filename of the config file without the file extension")
	configDirPath = flag.StringP("config-dir", "d", ".", "Path to the directory containing the config file")

	// viper
	NodeConfig *viper.Viper

	// logger
	defaultLoggerConfig = logger.Config{
		Level:             "info",
		DisableCaller:     false,
		DisableStacktrace: false,
		Encoding:          "console",
		OutputPaths:       []string{"goshimmer.log"},
		DisableEvents:     false,
	}
)

func init() {
	// set the default logger config
	NodeConfig = viper.New()
	NodeConfig.SetDefault(logger.ViperKey, defaultLoggerConfig)

	if err := Fetch(false); err != nil {
		panic(err)
	}
	parseParameters()
}

func parseParameters() {
	for _, pluginName := range NodeConfig.GetStringSlice(node.CFG_DISABLE_PLUGINS) {
		node.DisabledPlugins[node.GetPluginIdentifier(pluginName)] = true
	}
	for _, pluginName := range NodeConfig.GetStringSlice(node.CFG_ENABLE_PLUGINS) {
		node.EnabledPlugins[node.GetPluginIdentifier(pluginName)] = true
	}
}

// Fetch fetches config values from a dir defined via CLI flag --config-dir (or the current working dir if not set).
//
// It automatically reads in a single config file starting with "config" (can be changed via the --config CLI flag)
// and ending with: .json, .toml, .yaml or .yml (in this sequence).
func Fetch(printConfig bool, ignoreSettingsAtPrint ...[]string) error {
	err := parameter.LoadConfigFile(NodeConfig, *configDirPath, *configName, true, true)
	if err != nil {
		return err
	}

	if printConfig {
		parameter.PrintConfig(NodeConfig, ignoreSettingsAtPrint...)
	}
	return nil
}
