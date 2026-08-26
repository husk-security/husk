# Recorded OSV advisory records

Real records fetched from the live OSV API (api.osv.dev / the OSV GCS
mirror) on 2026-08-25, unmodified except JSON key sorting. `tests/intel.rs`
loads them into hand-built local mirror databases and asserts the mirror
path produces the same verdicts the live OSV API produces for known
affected and known fixed versions, including the NuGet name-case and
VSCode publisher-case traps.

These are advisory data, not detection fixtures: no scanner emits
coordinates from this directory.
