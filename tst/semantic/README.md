# Semantic version-comparison fixtures

Test fixtures vendored unmodified from Google's osv-scalibr project
(`semantic/testdata/`, Apache License 2.0, Copyright Google LLC; see
LICENSE in this directory). They validate `src/intel/semantic/`, a Rust
port of that package, against the upstream implementation's own corpus.

Each non-comment line is `<a> <op> <b>` where `<op>` is `<`, `=`, or `>`.
