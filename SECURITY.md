# Security policy

`routecheck` reads untrusted input from several sources:

- MRT files: session captures and route-collector RIB dumps downloaded from
  public collectors;
- IRR dump files, and the answers of a live IRRd;
- VRP JSON files;
- a local `-policy` draft.

Registry objects are written by anyone who holds a maintainer, AS-path regular
expressions included. Hostile or corrupt input must never do any of these to a
program that uses the library or runs the command:

- crash it;
- make it exhaust memory;
- keep it busy without bound;
- make it report a verdict the data does not support.

## Reporting a vulnerability

Please report it privately through GitHub:
**[Report a vulnerability](https://github.com/rkolesnichenko/routecheck/security/advisories/new)**
(also on the repository's Security tab). The report stays private between you
and the maintainer until an advisory is published. If you can't use GitHub,
email **rokolg@gmail.com** instead.

Include a minimal reproducer if you have one: the MRT bytes, the RPSL objects,
or a fuzz corpus entry. Public GitHub issues are not the right channel for an
embargoed report. Open an issue only after we've coordinated disclosure.

I'll acknowledge within 72 hours. For issues affecting decoding or matching
safety, I aim to have a fix candidate within two weeks. Timelines for other
classes of issue are negotiated case by case.

## What's already hardened

These are the invariants the library enforces. Treat a regression in any of
them as a security-relevant bug.

- **No panics on any input.** The code that takes untrusted input has fuzz
  targets: `FuzzMatch` (regexp text × path), `FuzzDecide` (policy × route) and
  `FuzzObserve` (MRT bytes, both modes). CI runs them on every push. Decoding MRT
  and RPSL is done by mrt and rpsl, which fuzz their own decoders.
- **The AS-path matcher is bounded.** `pathre` uses no `regexp` package and does
  no backtracking. It counts its work (`MatchOptions.MaxWork`, by default
  10,000,000 steps), so time and allocation are both bounded. Past the budget it
  returns `ErrTooExpensive`, and the route is Undecided (`path-too-expensive`),
  never a guess. An adversarial regexp is pinned to stop within 1 s.
- **Memory is bounded by the routes through X, not by the input.** MRT input is
  streamed. Only X's routes are held: one Adj-RIB-Out in session mode, and the
  deduplicated observations through X in collector mode. The verdict path memo
  is capped at 64 MiB of keys, and past the cap it is cleared. Set expansion is bounded
  by rpsl's limits; `-max-prefixes` raises one, at the user's choice and memory.
- **Malformed input is counted, never silently used.** A malformed UPDATE is
  handled as RFC 7606 says: treat-as-withdraw, or a session reset. A malformed RIB
  entry is skipped. Each is counted and reported. A decoded attribute the decoder
  flagged is never read as if it were whole.
- **Never guess.** A test that cannot be decided from the data makes the route
  Undecided, with the reason. A policy that cannot be evaluated is an error for
  the run, except a set reaching AS-ANY (or RS-ANY) in filter position, or a
  set over one of rpsl's expansion limits: each of those makes only its report
  "unevaluable". In an AS-path regexp such a set matches any one AS, and an
  accepted route names it (`AnySets`); the text output's report block names
  such sets and counts those routes whatever `-routes` lists, so the output
  shows that the path test let any AS through.
- **No network outside the command.** `pathre`, `verdict`, `observe`, `hygiene`
  and the `routecheck` package do not import `net`, which `check.sh` enforces.
  Only `internal/cli` and `cmd/routecheck` open files and, with `-irrd`, a
  connection to the IRRd the user names.

## Scope

In scope:

- Panics, memory exhaustion or unbounded CPU in `routecheck`, `pathre`,
  `verdict`, `observe`, `hygiene` or the command, on any input.
- A verdict that the data does not support. For example, a route Accepted or
  Rejected where a test was in fact undecided.

Out of scope:

- Bugs in mrt or rpsl themselves. Report those to those repositories, unless
  routecheck's use of them is the cause.
- The cost of expanding very large sets. That is rpsl's `resolve.Expander`, with
  its own limits.
- Decompression costs inherent in gzip or bzip2 themselves.
- What a live IRRd chooses to answer. It is trusted to be the registry you meant.
