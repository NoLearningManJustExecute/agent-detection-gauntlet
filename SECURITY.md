# Security

## Scope

agent-detection-gauntlet is a research tool. It measures how well detection rules hold up
against evasive attacks on AI agents. It is not a security product.

- During Phase 0 the repository ships synthetic data only. The fixture traces contain made-up
  prompt injection text and example addresses. They describe no real system or person.
- The tool is intended for local use only. It reads and writes local files. It is not designed,
  tested or supported for production monitoring, and it has no live SIEM integration.

## Trust model

Rules and traces are treated as trusted local input.

- Rule files are parsed with a safe YAML loader that builds only plain data, rejects duplicate
  keys, and validates the result strictly.
- Rule `regex` operators are compiled and run with Python's `re` module. There is no timeout or
  limit on backtracking, so a crafted pattern or a crafted trace can make a scan very slow. Do
  not load rules from untrusted sources.
- Trace, label and detection files are validated strictly against their schemas and fail closed
  on any problem, but they are not sandboxed. Treat trace content from unknown sources with the
  same care as any other untrusted data.
- The `metrics` command runs `git` in the directory the package is installed from to record the
  commit and dirty flag. It does not run any other external program.

## Reporting a vulnerability

Private vulnerability reporting will be enabled when the repository goes public. Until then, the repository is private.
