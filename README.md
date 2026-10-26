# Tenable API Field Guide

An agent skill that makes AI coding assistants write correct code against Tenable's APIs,
and diagnose integrations that misbehave. It works with Claude Code, Codex, Cursor, GitHub
Copilot and Gemini CLI.

Tenable's APIs differ by product in auth headers, paging, filter syntax and error behavior,
and several defaults quietly change results. An assistant working from memory typically
writes a vulnerability export that:

- returns only the last 30 days of data (there's a default time window),
- never includes fixed findings (the default `state`),
- polls forever if someone cancels the job,
- or retries a `409` that means "this export is already running".

pyTenable adds traps of its own. Misspelled credentials produce an unauthenticated client
instead of an error, defaults differ from the API's, and return types vary by module.

This skill gives the assistant rules checked against the public API reference at
[developer.tenable.com](https://developer.tenable.com) and against the pyTenable source,
so it gets these right the first time.

## What it covers

- **Auth and clients:** header and base URL per product, pyTenable constructors and env var
  prefixes, SSL, timeouts.
- **VM exports:** vulnerability, asset (v1/v2), compliance and WAS exports.
  - The lifecycle and status values.
  - Default time and state windows.
  - Filter syntax, including tag filters, which take one form for vulns and assets v1,
    another for compliance, and aren't supported on assets v2.
  - Chunk handling and expiry.
  - Duplicates (409).
  - Joining findings to assets, and reconciling deleted assets.
- **Limits:** rate limiting and `retry-after`, concurrency caps (10 exports, 3 detail calls,
  25 active scans), pyTenable's retry behavior, User-Agent identification.
- **Pagination:** the scheme for each API (VM, WAS, Tenable One, PCI ASV, ASM, Identity
  Exposure, Security Center, Cloud Security), plus record caps that force you onto exports.
- **pyTenable:** return types, silent failures, deprecated methods and their replacements,
  and Tenable One enum and sort quirks.
- **Security Center:** errors inside HTTP 200, analysis paging, filter tuples, the automatic
  WAS exclusion, asset lists, schedules and freeze windows.
- **Nessus:** the scan API licensing restriction on Professional and Expert and how to
  detect it, `null` lists, single-use export downloads, credential fields in scan details,
  and pyTenable's Nessus quirks.
- **Troubleshooting by symptom**, including behaviors confirmed against the live API where
  the documentation was wrong or incomplete.
- **Recipes:** an incremental vulnerability sync over raw HTTP, the same sync with pyTenable,
  an asset join, tag lookup and assignment, scan listing with paging, and SC analysis paging.

The skill is plain markdown: no scripts, no network access, nothing to run. The assistant
reads it while helping you.

## Prerequisites

One of the AI coding assistants below with agent skill support. The skill teaches the
assistant; to run the code it helps you write, you need your own Tenable API keys and,
optionally, [pyTenable](https://pypi.org/project/pytenable/) 26.10.1 or later.

## Installation

The skill is a folder containing `SKILL.md`, in the [Agent Skills](https://agentskills.io)
format. Clone it into the skills directory your assistant reads. The folder must keep the
name `tenable-api-field-guide`, because several platforms require the folder name to match
the skill name.

| Assistant | Personal (all projects) | One project | Docs |
|---|---|---|---|
| Claude Code | `~/.claude/skills/tenable-api-field-guide` | `.claude/skills/tenable-api-field-guide` | [Claude Code skills](https://docs.claude.com/en/docs/claude-code/skills) |
| Codex (CLI and IDE) | `~/.agents/skills/tenable-api-field-guide` | `.agents/skills/tenable-api-field-guide` | [Codex skills](https://learn.chatgpt.com/docs/build-skills) |
| Cursor | `~/.cursor/skills/tenable-api-field-guide` (or `~/.agents/skills/…`) | `.cursor/skills/tenable-api-field-guide` | [Cursor skills](https://cursor.com/docs/context/skills) |
| GitHub Copilot (VS Code) | `~/.copilot/skills/tenable-api-field-guide` (or `~/.agents/skills/…`) | `.github/skills/tenable-api-field-guide` | [Copilot agent skills](https://code.visualstudio.com/docs/copilot/customization/agent-skills) |
| Gemini CLI | `~/.gemini/skills/tenable-api-field-guide` (or `~/.agents/skills/…`) | `.gemini/skills/tenable-api-field-guide` | [Gemini CLI skills](https://geminicli.com/docs/cli/skills/) |

For example:

```bash
# Claude Code
git clone https://github.com/lanz/tenable-api-field-guide ~/.claude/skills/tenable-api-field-guide

# Codex, Cursor, GitHub Copilot and Gemini CLI all read ~/.agents/skills
git clone https://github.com/lanz/tenable-api-field-guide ~/.agents/skills/tenable-api-field-guide
```

On Windows, use `%USERPROFILE%\.claude\skills\…` or `%USERPROFILE%\.agents\skills\…`.
Restart the assistant, or run `/skills reload` in Gemini CLI, so it discovers the skill.

## How to use it

The assistant loads the skill on its own when you work on Tenable API code. Try:

> Write a Python job that syncs new and fixed vulnerabilities from Tenable VM every night.

> Our vuln export only returns open findings and we're missing everything older than a
> month. Why?

> This pyTenable script gets 401s on every call. Here's the code.

> Convert this Security Center analysis query to page through all results.

> Write a script that launches a scan on our Nessus Professional scanner.

You can also invoke it directly: `/tenable-api-field-guide` in Claude Code, Cursor and
GitHub Copilot, or `$tenable-api-field-guide` in Codex. Gemini CLI activates skills itself
and asks for consent the first time.

## Output

The skill produces no output of its own. It changes what the assistant writes. With the
skill loaded, generated code typically:

- sets `since` or an explicit `state`, so FIXED findings and older data aren't silently
  dropped
- handles `409` by reusing `active_job_id`, and `429` by sleeping for `retry-after`
- stops polling on `FINISHED`, `CANCELLED` or `ERROR`, with a deadline
- downloads chunks from `chunks_available` as they appear, instead of counting to
  `total_chunks`
- passes pyTenable's `include_unlicensed` and `num_assets` explicitly, and uses the right
  env var prefix
- checks Security Center's `error_code` even on HTTP 200
- checks a Nessus scanner's license for the scan API before automating scans

The assistant also explains which rule drove each non-obvious choice.

## Data handling

The skill contains no code that runs, and makes no network requests. It tells the assistant
never to hardcode, log or print API keys. Code the assistant writes from it calls only the
Tenable endpoints you ask for.

## Known limitations

- **Point-in-time accuracy.** The rules were checked against developer.tenable.com, live
  API behavior and pyTenable 26.10.1. APIs change, so check the official reference for
  anything critical. Issues and PRs with corrections are welcome.
- **Public APIs only.** It covers documented endpoints, and tells the assistant not to
  guess at others.
- **Security Center, Nessus and OT** have no OpenAPI spec on developer.tenable.com. Their
  rules come from live API behavior, the product user guides, and pyTenable's
  implementation, so coverage is thinner than for VM. A Nessus scanner documents its own
  API at `https://<scanner>:8834/api`.
- **Rate limits are dynamic.** Tenable publishes no fixed number, so the skill teaches
  `retry-after` handling, not a request budget.
- **Validated in testing:**
  - The recipes ran against Tenable VM containers, including the tag lookup and the tag
    assignment write, which was confirmed on the asset and then cleaned up. The Security
    Center recipe is only syntax-checked.
  - The install paths and invocation syntax for each platform follow that platform's
    documentation, linked above. Report an issue if one has changed.

## Development

```bash
pip install pytest pyyaml pytenable
pytest
```

The tests check:

- the skill's structure: the frontmatter rules for each platform, and that every referenced
  file exists
- that every Python example compiles
- that every pyTenable method the skill recommends exists in the installed pyTenable
- that no keys or internal references have slipped in

## License

Licensed under the [MIT License](LICENSE). Copyright (c) 2026 [Lance Duvall](https://github.com/lanz).

## Disclaimer

This is an independent open source community project. It is not an official Tenable
product and is not affiliated with, sponsored by, endorsed by, or supported by
Tenable, Inc.

Tenable, Nessus and other Tenable product names are trademarks or registered trademarks
of Tenable, Inc. Other names may be trademarks of their respective owners.
