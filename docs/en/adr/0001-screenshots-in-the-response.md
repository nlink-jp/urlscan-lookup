# ADR-0001: A screenshot comes back in the response; nothing is written to disk

- Status: Accepted
- Date: 2026-09-21

## Context

`get_screenshot` fetched a scan's PNG, **always wrote it into a directory** —
the caller's `workspace_root`, or the server's own `workspace_dir` when that was
omitted — and returned the path with the byte count. A screenshot at or below
4 MiB additionally rode back as MCP image content.

That is the shape the organization retired on 2026-09-06 (bigquery-mcp RFP
Item 2, fleet-wide):

> A server writing anything above a threshold into a file it chose, and
> returning the path, is retired. A server cannot know the caller's context
> window, and a threshold, a destination and a read-back path per server means
> the whole fleet reimplements the same mechanism. Putting a large response on
> disk is the agent runtime's job. What stays in a server is an explicit cap and
> the count of what it dropped.

Organization ADR-021 draws the same line: a server whose **product** is a file
keeps a work directory; a server that turns **data** into a file does not. A
screenshot this server fetches on request is data. pcap-analyzer-mcp applied the
decision in its ADR-0009 (`result_file`, `sample`, `delivery` removed, `work_dir`
kept because `extract_objects` produces files as its product); voice-scribe's
ADR-0011 removed its delivery-mode switch for the same reason.

This server was missed. The gap showed up from the other end: `workspace_root`
is also a retired ADR-021 §1 spelling, and while every other tool's arguments
were closed against unknown fields on 2026-09-21, this handler was left lenient
because a migration to `work_dir` was assumed to be pending. The migration is
not the answer — the argument should not exist.

The default destination made it plainer: `workspace_dir` pointed at the server's
own directory, so the reply's path was, in the common case, a path the caller
could not read.

## Decision

1. **A screenshot within the budget comes back as MCP image content.** That is
   what a model needs: it has to *see* the page.
2. **A screenshot above the budget is reported, not delivered.** The reply
   carries `bytes`, `inline: false`, a `note` naming the budget that stopped it,
   and `screenshot_url` — urlscan.io's own address for the PNG. It is not
   truncated: half a PNG is not a smaller picture, it is nothing. Fetching it is
   the runtime's or the person's business.
3. **Nothing is written to disk.** `workspace_root`, `workspace_dir`,
   `URLSCAN_LOOKUP_WORKSPACE` and `internal/workspace` are gone.
4. **The budget is the operator's**, `screenshot_max_bytes`
   (`URLSCAN_LOOKUP_SCREENSHOT_MAX_BYTES`), default 4 MiB — base64 inflates by a
   third and an inline image is replayed with the conversation every round.
   Stated from the inside, `[1, 64 MiB]`, so a NaN cannot pass a range check.
5. **`URLSCAN_LOOKUP_WORKSPACE` fails the load by name.** Ignoring it would
   delete a destination the operator believes is in force — pcap-analyzer's
   ADR-0009 §5 rule, applied here.
6. **`get_screenshot`'s arguments are closed** like every other tool's
   (ADR-021 §4): `additionalProperties: false` and a strict decoder. With
   `workspace_root` gone there is no retired spelling left to answer for, so the
   ADR's one-release grace has nothing to cover.

## Consequences

- **Breaking.** `screenshot_file` is gone from the reply, `workspace_root` from
  the arguments, and a configuration carrying `URLSCAN_LOOKUP_WORKSPACE` no
  longer starts. A caller that wants the file on disk saves the inline image, or
  fetches `screenshot_url`.
- A caller with a client that cannot take image content passes `inline: false`
  and gets the size and the URL.
- The server no longer has a writable directory at all, which removes it from
  ADR-021's work-directory contract entirely rather than migrating it.

## References

- Organization decision of 2026-09-06 (bigquery-mcp RFP Item 2); organization
  ADR-021 (the work-directory contract, and the file-as-product distinction)
- pcap-analyzer-mcp ADR-0009 (the same withdrawal, with `work_dir` kept),
  voice-scribe ADR-0011 (response cap, not a delivery mode)
