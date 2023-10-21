package options

type Options struct {
	// Prober options is a map keyed by purl types that holds free form structs
	// that are passed as options to the corresponding PackageProber.
	ProberOptions map[string]interface{}
}

var Default = Options{
	ProberOptions: map[string]interface{}{},
}
