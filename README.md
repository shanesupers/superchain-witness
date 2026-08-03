# SuperChain — independent witness

This repository is an **independent observer** of [SuperChain](https://superc.com),
the append-only ledger of superfile.com's `@name` / `.extension` registry.

It runs as a scheduled GitHub Action **on GitHub's infrastructure — not on the
operator's servers**. That is the entire point: a log you can only read through
its own operator proves nothing on its own. A second party, recording what it
saw somewhere the operator cannot reach, is what makes rewriting history
detectable.

## What each run checks

Every hour [`witness.mjs`](./witness.mjs) pulls the public checkpoints
([`/api/checkpoint/latest`](https://superc.com/api/checkpoint/latest) and
[`/history`](https://superc.com/api/checkpoint/history)) and, using only Node's
built-in crypto:

1. **Signatures** — re-verifies every checkpoint's **Ed25519** signature against
   the [pinned public key](./config.json). The key is pinned *here*, so even a
   key swap by the operator is flagged.
2. **Message honesty** — reconstructs the exact canonical body that was signed
   (`superc-sth/v1\n<tree_size>\n<head_block>\n<head_hash>\n<iso>`) and checks the
   published fields match it.
3. **Append-only** — no `head_block` this witness has *ever* recorded may change
   its hash, and the tree may never shrink. A changed past head is a **rewrite**.

It then appends what it saw to [`log/observations.ndjson`](./log/observations.ndjson).
The log is itself hash-chained (`witness_hash = sha256(prev + head_hash + tree_size + time)`)
and every append is a **git commit GitHub timestamps** — so this record is
tamper-evident on its own terms, independent of SuperChain.

## What it does *not* claim

- It does **not** verify the Bitcoin anchor itself. It records the operator's
  reported OpenTimestamps status (`ots_status`) — currently `pending` until the
  proof confirms into a Bitcoin block.
- A green run means "consistent with an honestly-appended log **as of the checks
  above**," not "decentralized." SuperChain remains an operator-run ledger; this
  witness narrows what the operator can get away with, it doesn't remove them.

## If something is wrong

A failed (red ✗) run means a signature failed or the log was rewritten. The run
opens an issue titled **⚠️ SuperChain divergence detected** with the evidence,
and the offending observation is committed with `"status":"DIVERGENCE"`.

Anyone can audit this independently: clone the repo, run `node witness.mjs`, and
compare against the live endpoints yourself.
