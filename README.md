# OpenVEX Discovery Module

This repository contains the OpenVEX discovery module. The module defines a 
_discovery agent_ that has pluggable modules to look for OpenVEX data associated
with a software component.

## Example Usage

```golang
package main

import (
	"fmt"
	"os"

	"github.com/openvex/discovery/pkg/discovery"
)

func main() {

	// Create a new agent
	agent := discovery.NewAgent()

	// Use the agent to probe the Kubernetes API server container image:
	vexDocuments, err := agent.ProbePurl(
		"pkg:oci/kube-apiserver?repository_url=registry.k8s.io&tag=v1.28.3",
	)

	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}

	// The prober returns a document collection. Print how many we got.
    fmt.Printf(
        "Found %d OpenVEX documents associated to package URL\n", len(vexDocuments),
    )

	for _, d := range vexDocuments {
		fmt.Printf(" > Document ID: %s\n", d.ID)
	}
}

```

## Operation

Just as SBOMs, VEX data can be stored in a variety of locations: git repositories.
oci registries, storage buckets, webservers, etc. Some locations make sense for
some software artifact types, some for others. Data can be referenced for example,
in another document like an SBOM or an OpenVEX document and may be living in a
different repository. The distributed nature of VEX makes this disemination possible.

### The OpenVEX discovery agent has two main jobs:

1. Understanding what kind of repositories may contain openvex data for different
component types.
2. Calling the relevant probers to look for and retrieve any OpenVEX documents
in locations associated with an artifact. 

## Module Status

We are slowly building backend drivers to support various use cases. The initial
release supports package urls of type `oci` but we will contantly add more. If
you want to support another type, feel free to open a pull request or file an 
issue!
