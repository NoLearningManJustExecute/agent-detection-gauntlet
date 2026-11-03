# Limitations

Read these with [findings.md](findings.md). They limit what the numbers can be taken to mean.

## Model and corpus

- **Single local model.** Every run used `llama3.1:8b`, digest
  `46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e`. What it does with encoded or
  mangled text says little about another model. Base64 breaking the attack, and three attack classes
  never succeeding, may both be properties of this model.
- **Single-author corpus.** One author wrote the attacks, the benign tasks, the variants and the rules.
  The split guards against fitting to specific traces, not against a shared view of what attacks look
  like.
- **Variant-group splits leave relatives across the split.** Whole groups go to one split, but 20 of 20
  succeeded held-out groups have a parent, sibling or seeded child in dev. They share the attack's
  mechanism and target, so clean recall may be inflated. The registered set-asides read 11/12 and 8/9,
  on few traces. With every relative set aside, in a row added after scoring, nothing is left to score.
- **Small samples.** 28 succeeded held-out traces in 20 groups. Per-class figures are all small-N, and
  AC06 and AC12A are flagged underpowered. The 38 benign traces are 19 groups run in two guardrail arms,
  and with guardrails off the combined false positive rate is 1/19 = 0.053.
- **Temperature 0.** Runs of one input mostly repeat, and repeats are removed, so more runs would not
  add independent evidence. Distinct inputs are the unit of independence. Wilson intervals treat traces
  as independent, so the group bootstrap intervals are the figures to read for comparisons.
- **Synthetic sandbox.** The agent runs against fixtures, not a real system. The names in traces are
  synthetic identities on the reserved `.test` domain, not real people; [dataset.md](dataset.md) lists
  them.

## Evasion

- **Paraphrase and translation are not measured as evasion.** They were spent seeding the corpus, so
  the rules were written against dev relatives of those wordings.
- **Base64 result is about this model.** Offline, with no model, bare base64 takes content rules from
  12/23 to 2/23. A model that can decode could make it a real evasion.
- **Survivors only.** Recall under mutation is measured on attacks that still worked. Where few survive,
  the row rests on few attacks.
- **Bases were selected for success.** Their attack success is near 1 by construction, so part of the
  drop in attack success is that selection.
- **Mechanical mutations.** They come from fixed code, not an adaptive attacker. An attacker who can see
  the rules could do better than these numbers show.
- **Splitting is within one message.** The agent takes one user message per run.
- **False positives are not re-measured.** Benign traces were not mutated, so false positive rates are
  from clean traces only.
- **A stricter oracle for two classes of variant.** AC01 and AC07 variants use a stricter oracle than
  those classes' baseline.
- **One success went to a garbled address.** One `split_chunks` input mailed an address the model
  garbled. Its oracle counts any outsider, so it is a success as registered. Two kept traces also had
  model-written text changed at export. See record 3 in [heldout-log.md](heldout-log.md).

## Detection and telemetry

- **Overlap-based provenance.** Content references need verbatim overlap of at least K characters.
  Paraphrased data flow is missed, and a mutated payload breaks links by construction. The sequence tier
  scored 6/28 at K=16 and K=24, and 2/28 at K=48.
- **Trust in the instrumentation.** Traces are taken as what the instrumented agent recorded, on first
  sight, with nothing authenticating them. Sequence rules are only as good as the links recorded, and an
  agent or tool that lies to its telemetry is out of scope.
- **Guardrails are labeled per trace,** not per action.
- **Precision depends on the corpus mix.** The share of attacks here is a property of this corpus, not
  of any deployment. No real alert volume was measured.
- **OpenTelemetry GenAI conventions are experimental.** The schema is pinned to one version.

## Exports and mappings

- **Converted SIEM rules are not live validated.** Sigma, KQL, SPL and ES|QL files are labeled
  "converted, not live SIEM validated". No SIEM or Sigma backend has run them. A round-trip test shows
  the Sigma parses and says what was meant, and nothing more. Most rules do not convert, and those that
  do assume an ingest pipeline that does not exist. See [export.md](export.md).
- **The release workflow has never been dispatched.**
- **One rule mapping is unverified, and OWASP LLM uses the 2025 numbers.** IDs quoted from the source
  threat model are outside that check, apart from what [mappings.md](mappings.md) notes. A rule's mapping
  is its author's claim about the technique it detects.

## Process

The access log in [heldout-log.md](heldout-log.md) records every held-out read and the errors found
along the way, including three log rows discarded by mistake and not written back. The post-registration
fixes are listed as errata in [preregistration.md](preregistration.md).
