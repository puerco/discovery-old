package oci

import (
	"testing"

	"github.com/openvex/discovery/pkg/discovery/options"
	purl "github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/require"
)

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
