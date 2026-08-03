#!/usr/bin/env node
// SuperChain independent witness.
//
// Runs on GitHub's infrastructure — NOT on the operator's servers. Every run it
// pulls SuperChain's signed checkpoints, independently re-verifies the Ed25519
// signatures with a PINNED public key, and proves the log only ever appended:
// no head hash it has ever seen may change, and the tree only grows. It then
// appends what it saw to a public, hash-chained log in this repo, which GitHub
// timestamps in git history. Because that record lives outside the operator's
// control, the operator cannot later rewrite SuperChain's history without
// contradicting this witness. Any violation fails the run (red ✗) loudly.
//
// No dependencies — Node's built-in crypto + fetch only.

import { readFileSync, writeFileSync, existsSync, appendFileSync } from "node:fs";
import { verify as edVerify, createPublicKey, createHash } from "node:crypto";

const cfg = JSON.parse(readFileSync(new URL("./config.json", import.meta.url)));
const STATE = new URL("./log/state.json", import.meta.url);
const OBS = new URL("./log/observations.ndjson", import.meta.url);

const problems = [];
const fail = (m) => problems.push(m);

// Reconstruct an Ed25519 public key from its raw 32 bytes (SPKI-wrapped) and
// verify a signature over the exact signed body. This is the same check any
// third party can run — it needs nothing from the operator but the public key.
function verifyEd25519(pubB64, body, sigB64) {
  try {
    const raw = Buffer.from(pubB64, "base64");
    if (raw.length !== 32) return false;
    const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
    const key = createPublicKey({ key: spki, format: "der", type: "spki" });
    return edVerify(null, Buffer.from(body, "utf8"), key, Buffer.from(sigB64, "base64"));
  } catch { return false; }
}

async function getJSON(url) {
  const r = await fetch(url, { headers: { "user-agent": "superchain-witness" } });
  if (!r.ok) throw new Error(`${url} → HTTP ${r.status}`);
  return r.json();
}

// A checkpoint's JSON fields must match what was actually SIGNED. The signed
// body is authoritative: "superc-sth/v1\n<tree_size>\n<head_block>\n<head_hash>\n<iso>".
function parseSignedBody(body) {
  const p = String(body).split("\n");
  if (p[0] !== cfg.signed_body_prefix) return null;
  return { tree_size: Number(p[1]), head_block: Number(p[2]), head_hash: p[3], created_at: p[4] };
}

// The canonical message the operator signs. History rows don't ship the signed
// body, so the witness reconstructs it from the fields and verifies with the
// PINNED key — a stronger check than trusting an operator-supplied string. The
// Postgres timestamp normalizes to the exact signed form via toISOString().
function reconstructBody(row) {
  return `${cfg.signed_body_prefix}\n${row.tree_size}\n${row.head_block}\n${row.head_hash}\n${new Date(row.created_at).toISOString()}`;
}

function checkCheckpoint(cp, label) {
  if (!cp) return null;
  // Key: use the operator's stated key only to flag a swap; always verify
  // against the pinned key so a swapped key can never pass.
  if (cp.pubkey && cp.pubkey !== cfg.pinned_pubkey)
    fail(`${label}: operator key changed (${cp.pubkey}) — expected pinned ${cfg.pinned_pubkey}`);
  const body = cp.signed_body ?? reconstructBody(cp);
  if (!verifyEd25519(cfg.pinned_pubkey, body, cp.signature))
    fail(`${label}: Ed25519 signature INVALID for head #${cp.head_block}`);
  const s = parseSignedBody(body);
  if (!s) { fail(`${label}: unrecognized signed body`); return null; }
  // When the operator shipped a full body, its JSON fields must not disagree.
  if (cp.signed_body) {
    if (Number(cp.head_block) !== s.head_block) fail(`${label}: head_block JSON≠signed (${cp.head_block}≠${s.head_block})`);
    if (String(cp.head_hash) !== s.head_hash) fail(`${label}: head_hash JSON≠signed`);
    if (Number(cp.tree_size) !== s.tree_size) fail(`${label}: tree_size JSON≠signed (${cp.tree_size}≠${s.tree_size})`);
  }
  return s;
}

const nowISO = () => new Date().toISOString();

async function main() {
  const state = existsSync(STATE)
    ? JSON.parse(readFileSync(STATE))
    : { seen: {}, last_tree_size: 0, last_head_block: 0, witness_hash: "genesis", runs: 0 };

  let latest, history;
  try {
    latest = (await getJSON(cfg.latest_endpoint)).checkpoint;
    history = (await getJSON(cfg.history_endpoint)).checkpoints ?? [];
  } catch (e) {
    // Reachability failure is not divergence — record it and exit clean so a
    // transient outage doesn't cry wolf.
    console.log(`unreachable: ${e.message}`);
    appendFileSync(OBS, JSON.stringify({ t: nowISO(), status: "unreachable", error: e.message }) + "\n");
    return 0;
  }

  if (!latest) { console.log("no checkpoint published yet — nothing to witness"); return 0; }

  // Verify every checkpoint we can see (signatures + JSON↔signed agreement).
  for (const cp of history) checkCheckpoint(cp, `history#${cp.head_block}`);
  const s = checkCheckpoint(latest, "latest");

  // Append-only proof: nothing previously witnessed may change.
  for (const cp of history) {
    const k = String(cp.head_block);
    if (state.seen[k] && state.seen[k] !== cp.head_hash)
      fail(`REWRITE: head #${k} was ${state.seen[k]}, now ${cp.head_hash}`);
  }
  if (s) {
    const k = String(s.head_block);
    if (state.seen[k] && state.seen[k] !== s.head_hash)
      fail(`REWRITE: head #${k} was ${state.seen[k]}, now ${s.head_hash}`);
    // The tree must never shrink.
    if (s.tree_size < state.last_tree_size)
      fail(`SHRINK: tree_size ${s.tree_size} < last witnessed ${state.last_tree_size}`);
    if (s.head_block < state.last_head_block)
      fail(`SHRINK: head_block ${s.head_block} < last witnessed ${state.last_head_block}`);
  }

  const diverged = problems.length > 0;
  const sigOK = s && verifyEd25519(latest.pubkey, latest.signed_body, latest.signature);

  // Record everything we saw (even on divergence — the evidence is the point).
  if (s) { state.seen[String(s.head_block)] = s.head_hash;
    state.last_tree_size = Math.max(state.last_tree_size, s.tree_size);
    state.last_head_block = Math.max(state.last_head_block, s.head_block); }
  for (const cp of history) state.seen[String(cp.head_block)] = cp.head_hash;
  state.runs += 1;

  // The witness log is itself hash-chained, independent of SuperChain: each
  // observation commits to the previous one, so this public record is tamper-
  // evident on its own terms too.
  const obs = {
    t: nowISO(),
    status: diverged ? "DIVERGENCE" : "ok",
    head_block: s?.head_block ?? null,
    head_hash: s?.head_hash ?? null,
    tree_size: s?.tree_size ?? null,
    signature_valid: !!sigOK,
    ots_status: latest.ots_status ?? null,          // 'pending' until Bitcoin-confirmed
    ots_btc_block: latest.ots_btc_block ?? null,
    checkpoints_checked: history.length,
    prev_witness_hash: state.witness_hash,
  };
  obs.witness_hash = createHash("sha256")
    .update(state.witness_hash + "|" + (obs.head_hash ?? "") + "|" + (obs.tree_size ?? "") + "|" + obs.t)
    .digest("hex");
  state.witness_hash = obs.witness_hash;

  if (diverged) obs.problems = problems;
  appendFileSync(OBS, JSON.stringify(obs) + "\n");
  writeFileSync(STATE, JSON.stringify(state, null, 2) + "\n");

  console.log(`witness run #${state.runs}: head #${obs.head_block} tree ${obs.tree_size} ` +
    `sig=${obs.signature_valid ? "valid" : "INVALID"} ots=${obs.ots_status} ` +
    `checkpoints=${history.length} → ${obs.status}`);

  if (diverged) {
    console.error("\n✗ DIVERGENCE / signature failure:");
    for (const p of problems) console.error("  - " + p);
    return 1;
  }
  return 0;
}

main().then((code) => process.exit(code)).catch((e) => {
  console.error("witness crashed:", e);
  process.exit(2);
});
