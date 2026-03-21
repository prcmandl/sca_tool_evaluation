#!/usr/bin/env bash
set +e

# $1 = SBOM path passed by adapters
/usr/local/bin/snyk sbom test --experimental --file="$1" --json
