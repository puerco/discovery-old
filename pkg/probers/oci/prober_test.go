package oci

import (
	"fmt"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/openvex/discovery/pkg/discovery/options"
	"github.com/openvex/discovery/pkg/probers/oci/ocifakes"
	"github.com/openvex/go-vex/pkg/vex"
	purl "github.com/package-url/packageurl-go"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/stretchr/testify/require"
)

func TestDownloadDocuments(t *testing.T) {
	impl := defaultImplementation{}
	// DownloadDocuments(options.Options, oci.SignedEntity) ([]*vex.VEX, error)
	for _, tc := range []struct {
		name      string
		options   options.Options
		reference string
		numDocs   int
		mustErr   bool
	}{
		{
			name:      "image with openvex",
			options:   options.Default,
			reference: "localhost:5000/wolfi-base:latest",
			numDocs:   1,
			mustErr:   false,
		},
		{
			name:      "no attestations",
			options:   options.Default,
			reference: "localhost:5000/notsigned:latest",
			mustErr:   false,
			numDocs:   0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref, err := name.ParseReference(tc.reference)
			require.NoError(t, err)
			se, err := ociremote.SignedEntity(ref)
			require.NoError(t, err)

			docs, err := impl.DownloadDocuments(tc.options, se)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, docs, tc.numDocs)
		})
	}
}

func TestPurlToRefString(t *testing.T) {
	for n, tc := range map[string]struct {
		testInput         string
		expectedReference string
		options           localOptions
		mustError         bool
	}{
		"normal": {
			"pkg:oci/curl@sha256%3A47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c",
			"curl@sha256:47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c",
			localOptions{},
			false,
		},
		"normal-with-repo": {
			"pkg:oci/curl@sha256%3A47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c?repository_url=cgr.dev/chainguard/",
			"cgr.dev/chainguard/curl@sha256:47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c",
			localOptions{},
			false,
		},
		"latest": {
			"pkg:oci/debian:latest",
			"debian:latest",
			localOptions{},
			false,
		},
		"tag-and-digest": {
			"pkg:oci/debian@sha256%3A47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c?tag=latest",
			"debian@sha256:47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c",
			localOptions{},
			false,
		},
		"non-oci": {
			"pkg:apk/wolfi/ca-certificates-bundle@20230506-r0?arch=x86_64",
			"",
			localOptions{},
			true,
		},
		"invalid": {
			"Hello !",
			"",
			localOptions{},
			true,
		},
		"repo-in-opts": {
			"pkg:oci/debian:latest",
			"cgr.dev/debian:latest",
			localOptions{Repository: "cgr.dev/"},
			false,
		},
		"repo-override": {
			"pkg:oci/pause:latest?repository_url=k8s.gcr.io/",
			"registry.k8s.io/release/pause:latest",
			localOptions{RepositoryOverride: "registry.k8s.io/release/"},
			false,
		},
	} {
		p, err := purl.FromString(tc.testInput)
		if !tc.mustError {
			require.NoError(t, err, n)
		}
		opts := options.Default
		opts.ProberOptions[purl.TypeOCI] = tc.options
		ref, err := purlToRefString(opts, p)
		if tc.mustError {
			require.Error(t, err, n)
			continue
		}

		require.Equal(t, tc.expectedReference, ref)
	}
}

func TestFindDocumentsFromPurl(t *testing.T) {
	prober := New()
	p, err := purl.FromString("pkg:oci/scratch@sha256%3A0000000000000000000000000000000000000000000000000000000000000000")
	require.NoError(t, err)
	syntErr := fmt.Errorf("synthetic error")
	for _, tc := range []struct {
		name    string
		options options.Options
		prepare func(*Prober)
		mustErr bool
	}{
		{
			name: "success",
			prepare: func(p *Prober) {
				impl := &ocifakes.FakeOciImplementation{}
				impl.PurlToReferenceReturns(name.MustParseReference("scratch"), nil)
				impl.DownloadDocumentsReturns([]*vex.VEX{{}}, nil)
				p.impl = impl
			},
		},
		{
			name: "purltoreference fails",
			prepare: func(p *Prober) {
				impl := &ocifakes.FakeOciImplementation{}
				impl.PurlToReferenceReturns(nil, syntErr)
				p.impl = impl
			},
			mustErr: true,
		},
		{
			name: "resolveimagereference fails",
			prepare: func(p *Prober) {
				impl := &ocifakes.FakeOciImplementation{}
				impl.ResolveImageReferenceReturns(nil, syntErr)
				p.impl = impl
			},
			mustErr: true,
		},
		{
			name: "dowenloaddocuments fails",
			prepare: func(p *Prober) {
				impl := &ocifakes.FakeOciImplementation{}
				impl.DownloadDocumentsReturns(nil, syntErr)
				p.impl = impl
			},
			mustErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.prepare(prober)
			docs, err := prober.FindDocumentsFromPurl(tc.options, p)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, docs)
		})
	}
}
