package dto

import (
	"context"

	devstdout "github.com/containerscrew/devstdout/pkg"
)

type ContextData struct {
	Log    *devstdout.CustomLogger
	Config *Config
}

// Define a custom key type to avoid string-based key issues
type contextKey string

const ContextDataKey = contextKey("contextData")

// Retrieve context data (log and config) from the context
func GetContextData(ctx context.Context) *ContextData {
	contextData, _ := ctx.Value(ContextDataKey).(*ContextData)
	return contextData
}