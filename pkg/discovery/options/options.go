package options

import (
	"context"
	"log/slog"
	"os"
)

type Options struct {
	Logger  *slog.Logger
	Context context.Context
	// Prober options is a map keyed by purl types that holds free form structs
	// that are passed as options to the corresponding PackageProber.
	ProberOptions map[string]interface{}
}

var Default = Options{
	Logger:        slog.New(slog.NewJSONHandler(os.Stderr, nil)),
	ProberOptions: map[string]interface{}{},
}