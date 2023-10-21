package discovery

import (
	"fmt"
	"sync"

	"github.com/openvex/go-vex/pkg/vex"
	purl "github.com/package-url/packageurl-go"

	"github.com/openvex/discovery/pkg/probers/oci"

	"github.com/openvex/discovery/pkg/discovery/options"
)

var (
	regMtx  sync.RWMutex
	probers = map[string]VexProbe{}
)

func init() {
	RegisterDriver(purl.TypeOCI, oci.New())
}

func RegisterDriver(purlType string, probe VexProbe) {
	regMtx.Lock()
	probers[purlType] = probe
	regMtx.Unlock()
}

// Probe is the main object that inspects repositories and looks for security
// documents. To create a new Probe use the `NewProbe` function
type Agent struct {
	impl    agentImplementation
	Options options.Options
}

// NewAgent creates a new discovery agent
func NewAgent() *Agent {
	return &Agent{
		impl:    &defaultAgentImplementation{},
		Options: options.Options{},
	}
}

// Fetch probes the package url using a package prober and retrieves all the
// security documents it can find.
func (agent *Agent) Probe(product vex.Component) ([]*vex.VEX, error) {
	// TODO: Support other types of identifiers
	if _, ok := product.Identifiers[vex.PURL]; !ok {
		return nil, fmt.Errorf("the product does not have a supported identifier")
	}
	purlString := product.Identifiers[vex.PURL]
	p, err := agent.impl.ParsePurl(purlString)
	if err != nil {
		return nil, fmt.Errorf("validating purl: %w", err)
	}

	pkgProbe, err := agent.impl.GetPackageProbe(agent.Options, p)
	if err != nil {
		return nil, fmt.Errorf("getting package probe for purl type %s: %w", p.Type, err)
	}

	docs, err := agent.impl.FetchDocuments(agent.Options, pkgProbe, p)
	if err != nil {
		return nil, fmt.Errorf("fetching documents: %w", err)
	}

	return docs, nil
}
