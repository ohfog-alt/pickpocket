# Pickpocket

Pickpocket is proof-of-concept validation tooling for Codex auth storage and app-server auth-status exposure.

## Research Use and Disclosure

This repository is proof-of-concept research published for educational and defensive purposes. The security issues demonstrated by this research were disclosed through OpenAI's formal reporting channels, followed by repeated attempts over several months to engage on remediation. It is being released so security practitioners can independently understand the risk, challenge their assumptions, and improve their defenses. Test only with accounts and systems you are authorized to use.

This is intentionally not production tooling. It can retrieve live account credentials, uses an unsupported product interface that can change without notice, and is provided as-is.

Research write-up: [Living Off the Agent Pt 2](https://ohfog.com/2026/10/09/living-off-the-agent-pt-2-obtaining-and-using-the-codex-agent-identity/)

- [codex-pickpocket.py](codex-pickpocket.py) is an audit-only harness that starts
  a loopback app-server listener, verifies `getAuthStatus` reachability with
  `includeToken:false`, writes a non-secret report, and shuts the listener down.
  Use `--refresh-token` to exercise the refresh path before collecting metadata.

With `--includeToken`, stdout is a canonical JSON handoff that Plugout accepts
with `--auth-file`; report metadata is written to stderr:

```text
python3 codex-pickpocket.py --includeToken > pickpocket-auth.json
python3 ../plugout/plugout.py --auth-file pickpocket-auth.json list-connectors
```
