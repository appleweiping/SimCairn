# Security Policy

## Reporting

Use GitHub private vulnerability reporting. Do not publish an exploit involving
path escape, command injection, secret exposure, cache poisoning, unsafe resume,
or uncontrolled subprocesses before a coordinated fix is available.

Include a minimal synthetic manifest, operating system, Python version, affected
release, observed behavior, and impact. Acknowledgement and coordinated
disclosure timing depend on maintainer availability, impact, and reproducibility.

## Security model

Manifests are trusted operational configuration because they select a simulator
binary. SimCairn does not claim to sandbox that binary. It does avoid shell
interpretation, confines declared files, allowlists inherited environment,
limits subprocess duration, validates persisted paths, and hashes artifacts.

Run untrusted binaries or netlists under an operating-system sandbox, container,
or restricted account. Do not put credentials directly in a committed manifest.
