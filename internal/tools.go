// SPDX-FileCopyrightText: Copyright 2022 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0
//go:build tools

// This is used to import things required by build scripts, to force `go mod`
// to see them as dependencies

package internal

import (
	_ "github.com/maxbrunsfeld/counterfeiter/v6"
)
