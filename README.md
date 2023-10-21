# OpenVEX Discovery Module

This repository contains the OpenVEX discovery module. The module defines a 
_discovery agent_ that has pluggable modules to look for OpenVEX data associated
with a software component.

## Operation

Just as SBOMs, VEX data can be stored in a variety of locations: git repositories.
oci registry, storage buckets, webservers, etc. Some locations make sense for
some software artifacts, some for others. Data can be referenced for example,
in another document like an SBOM or an OpenVEX document and may be living in a
different repository. The distributed nature of VEX makes this disemination possible.

The OpenvVEX discovery agent has two main jobs:

1. Understanding what kind of repositories may contain openvex data for different
component types.
2. Calling the relevant probers to look for and retrieve any OpenVEX documents
in locations associated with an artifact. 

## Status

This module is still a POC. We have just a few probers written to test 
integrating the library with openvex The API will keep changing.
