# Jot release acceptance — 2026-09-08

Add public reusable workflow entry points for the Jot acceptance harness. Both
the chirpauth and stackwell-labs organizations need to call them; private
source remains authenticated with the existing CI App.

Candidate builds use explicit SHAs and four real routers, with a required
browser journey. Post-release checks dispatch and await one serialized live
workflow in Jot. No caller can pass by skipping an unavailable check.

Actionlint passes for both new reusable workflows. Local positive and deliberately
broken candidates are exercised in Jot. Next: commit, pin caller workflows to
this revision, and demonstrate hosted failed-gate → skipped-publication behavior.
