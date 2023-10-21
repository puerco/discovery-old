package discovery

import (
	"github.com/openvex/go-vex/pkg/vex"
	purl "github.com/package-url/packageurl-go"

	"github.com/openvex/discovery/pkg/discovery/options"
)

type VexProbe interface {
	FetchDocuments(options.Options, purl.PackageURL) ([]*vex.VEX, error)
	SetOptions(options.Options)
}
