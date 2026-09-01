# Getting help with Trench

## Start here

| What you have | Where it goes |
| --- | --- |
| A question, or a config that will not do what you want | [Discussions → Q&A](https://github.com/dev-doshi/trench/discussions/categories/q-a) |
| A security vulnerability | [Private advisory](https://github.com/dev-doshi/trench/security/advisories/new) — never a public issue |
| Something is broken | [Open an issue](https://github.com/dev-doshi/trench/issues/new/choose) |
| A site is wrongly blocked, or something slips through | The *Filtering: wrong verdict* form |
| A name will not resolve at all | The *Resolution failure* form |
| It got OOM-killed, or memory keeps growing | The *Performance, memory, or stability* form |
| An idea | The *Feature request* form |

The [documentation](https://dev-doshi.github.io/trench/) covers installation,
the full configuration reference, the CLI, the API, and troubleshooting. It is
built from `docs/` in this repository and a broken link fails CI, so if a page
contradicts the software, that is a bug worth reporting.

## What makes a report actionable

Three commands answer most of what anyone triaging will ask, and running them
before you file usually shortens the whole exchange to nothing:

```bash
trench --version                    # exact version
trench explain <name>               # the rule, the list it came from, the policy
dig @<your-trench> <name> <type> +dnssec
```

For anything that fails intermittently, `log.level: debug` in `trench.yaml`
turns the resolver's own reasoning into log lines — the DNSSEC validator, for
instance, names the link in the chain that failed, which is usually the whole
report.

Please redact before pasting. A query log records every hostname a device on
your network looked up, and a config can carry TLS keys, TSIG secrets and API
tokens.

## What to expect

This is a small project. Issues are read, but not on a schedule, and the
answer to a feature request is sometimes "no, and here is why". A defect with
a reproduction gets attention ahead of a report without one, simply because it
can be worked on.

Two conventions worth knowing:

* **Blocklists are other people's data.** If a name is blocked by an upstream
  list — HaGeZi, StevenBlack, OISD — the fix belongs with that list. Report it
  here when Trench applied the list incorrectly, which is a different bug.
* **Nothing is closed for being old.** Only issues waiting on their reporter
  are swept, and reopening one takes a comment.

## Contributing a fix

`CONTRIBUTING.md` has the setup, the gates your change has to pass, and what a
good change looks like here.
