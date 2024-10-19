package main

import (
	"context"
	"fmt"

	devstdout "github.com/containerscrew/devstdout/pkg"
	"github.com/containerscrew/ebpfw/dto"
	"github.com/containerscrew/ebpfw/tracker"
)


func main(){
	// Read config file
	config, err := dto.ReadConfigFile()
	if err != nil {
		panic(err)
	}

	log := devstdout.NewLogger(
		devstdout.OptionsLogger{Level: config.Log.Level, AddSource: false, LoggerType: config.Log.Type},
	)

	log.Info("Starting ebpfw")
	log.Info(fmt.Sprintf("%v", config.Firewall))

	// Create a struct to hold both log and config
	contextData := &dto.ContextData{
		Log:    log,
		Config: &config,
	}

	// Add the contextData struct to the context using the custom key
	ctx := context.WithValue(context.Background(), dto.ContextDataKey, contextData)

	tracker.StartNetworkTracking(ctx)
}