# End-to-End Test Fixtures

## Fixtures to test the OCI Backend

When running the e2e OCI tests, the workflow will setup a registry and push a few
test images that can be used to test access, matching, etc:

#### localhost:5000/wolfi-base:latest

This is a signed image with an SBOM and an openvex attestation

#### localhost:5000/alpine-cves

This is an alpine-base image with knwown CVEs (CVE-2023-5363 and CVE-2023-5678).
It has an attached openvex document that naks them, the first using the purl of
the multiarch image index and the second using the reference of the linux/amd64
variant. The VEX document is 
[checked in the repository](testdata/alpine-cves.openvex.json).
