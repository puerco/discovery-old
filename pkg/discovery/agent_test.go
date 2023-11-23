package discovery_test

import (
	"fmt"
	"testing"

	"github.com/openvex/discovery/pkg/discovery"
	"github.com/openvex/discovery/pkg/discovery/discoveryfakes"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/require"
)

func TestProbeComponent(t *testing.T) {
	syntErr := fmt.Errorf("synthetic error")
	comp := vex.Component{
		Identifiers: map[vex.IdentifierType]string{
			vex.PURL: "pkg:oci/scratch@sha256%3A0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	for _, tc := range []struct {
		name    string
		prepare func(*discovery.Agent)
		mustErr bool
	}{
		{
			name: "success",
			prepare: func(a *discovery.Agent) {
				impl := &discoveryfakes.FakeAgentImplementation{}
				impl.FindDocumentsFromPurlReturns([]*vex.VEX{{}}, nil)
				a.SetImplementation(impl)
			},
			mustErr: false,
		},
		{
			name: "parsepParsePurl fails",
			prepare: func(a *discovery.Agent) {
				impl := &discoveryfakes.FakeAgentImplementation{}
				impl.ParsePurlReturns(packageurl.PackageURL{}, syntErr)
				a.SetImplementation(impl)
			},
			mustErr: true,
		},
		{
			name: "GetPackageProbe fails",
			prepare: func(a *discovery.Agent) {
				impl := &discoveryfakes.FakeAgentImplementation{}
				impl.GetPackageProbeReturns(nil, syntErr)
				a.SetImplementation(impl)
			},
			mustErr: true,
		},
		{
			name: "FindDocumentsFromPurl fails",
			prepare: func(a *discovery.Agent) {
				impl := &discoveryfakes.FakeAgentImplementation{}
				impl.FindDocumentsFromPurlReturns(nil, syntErr)
				a.SetImplementation(impl)
			},
			mustErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agent := discovery.NewAgent()
			tc.prepare(agent)
			docs, err := agent.ProbeComponent(comp)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, docs)
		})
	}
}
