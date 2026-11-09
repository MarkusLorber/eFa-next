# CycloneDX 1.5 JSON schema

The schema files of the CycloneDX specification, tag `1.5`, from
`https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/` (bom-1.5.schema.json, spdx.schema.json,
jsf-0.82.schema.json), fetched on 2026-11-08. License: Apache-2.0 (`third-party/licenses/Apache-2.0.txt`), copyright the
CycloneDX project (OWASP Foundation). Used only at build time by `build/sbom.py` to check the SBOM; not part of the packages.

`SHA256SUMS` pins them: build/sbom.py refuses files that do not match. A newer schema comes only in a separate change of this
folder (fetch, compare, new SHA256SUMS), never during a build.
