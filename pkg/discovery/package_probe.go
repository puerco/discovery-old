// SPDX-FileCopyrightText: Copyright 2022 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"github.com/openvex/go-vex/pkg/vex"
	purl "github.com/package-url/packageurl-go"

	"github.com/openvex/discovery/pkg/discovery/options"
)

type VexProbe interface {
	FindDocumentsFromPurl(options.Options, purl.PackageURL) ([]*vex.VEX, error)
	SetOptions(options.Options)
}
