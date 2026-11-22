# OSCAL 1.1.2 component-definition JSON schema

`oscal_component_schema.json` of the NIST OSCAL release `v1.1.2`, from
`https://github.com/usnistgov/OSCAL/releases/download/v1.1.2/oscal_component_schema.json`, fetched on 2026-11-19.
License: public domain (work of the US government, NIST; see the LICENSE.md of usnistgov/OSCAL). Used only at build time by
`scripts/compliance_build.py` to check the OSCAL export of the compliance file; not part of the packages.

`SHA256SUMS` pins it: compliance_build.py refuses a file that does not match. A newer schema comes only in a separate change of
this folder (fetch, compare, new SHA256SUMS), never during a build.
