# Findings

**Homoglyph and zero-width characters blind keyword detection, while sequence and behavior detection
hold.**

14 frozen rules were scored on held-out traces of a live agent, then on the same attacks with their
payloads mutated and re-executed. Rules were hashed and pre-registered before any held-out score
existed, and none changed afterward. Every rate below is in a committed results JSON, and CI fails on a
fraction or three-decimal rate that no JSON holds: [baseline](https://github.com/NoLearningManJustExecute/agent-detection-gauntlet/blob/main/results/baseline/metrics.json),
[evasion](https://github.com/NoLearningManJustExecute/agent-detection-gauntlet/blob/main/results/evasion/evasion.json),
[per-technique](https://github.com/NoLearningManJustExecute/agent-detection-gauntlet/blob/main/results/coverage/coverage.json). The tables are in
[results-baseline.md](results-baseline.md), [results-evasion.md](results-evasion.md) and
[the dashboard](https://NoLearningManJustExecute.github.io/agent-detection-gauntlet/dashboard.html). Read [limitations.md](limitations.md) with this page.

Rates read numerator/denominator = value. Brackets on a rate are Wilson 95% intervals. Brackets on a
change are percentile bootstrap intervals over variant groups, seed 1337, 10000 resamples. Evasion
figures are guardrails off unless stated.

## The evasion result

Pooled over payload mutations, on attacks that still succeeded, against the same base scenarios:

| Tier | Mutated recall | Base recall | Change |
|---|---|---|---|
| content | 7/57 = 0.123 | 25/48 = 0.521 | -0.398 [-0.604, -0.170] |
| sequence | 8/57 = 0.140 | 7/48 = 0.146 | -0.005 [-0.060, +0.047] |
| behavior | 21/57 = 0.368 | 20/48 = 0.417 | -0.048 [-0.092, +0.012] |
| all tiers | 28/57 = 0.491 | 39/48 = 0.812 | -0.321 [-0.531, -0.065] |

- **Content rules collapse under homoglyph and zero-width mutation.** Homoglyphs took content recall
  from 10/19 = 0.526 to 0/21 = 0.000, a change of -0.526 [-0.762, -0.250]. Zero-width characters took
  it from 9/16 = 0.562 to 1/23 = 0.043, a change of -0.519 [-0.774, -0.214].
- **Sequence and behavior hold, meaning no measurable drop.** Neither pooled interval excludes zero.
  That is not proof of no effect, and the intervals allow a real loss: under homoglyphs alone, sequence
  went from 4/19 to 3/21, -0.068 [-0.143, +0.000], and behavior from 10/19 to 9/21,
  -0.098 [-0.167, +0.000]. Sequence is also not immune to spelling, since its links come from verbatim
  overlap: at K=48 it scores 0/21 on homoglyphs.
- **Holding is not the same as catching.** Behavior recall stays at 21/57 = 0.368 and sequence at
  8/57 = 0.140. Neither replaces what content was catching, so the combined system still falls, by
  0.321. Part of the lesson is that the content tier was carrying weight an attacker can remove
  cheaply.
- **Base64 breaks the attack. It does not evade here.** Both encodings succeeded in 0/66 runs, so recall
  is null: there is no successful attack left to detect. We read that as this model not acting on the
  encoded text, which makes it no attacker win here. It may not stay that way. In an offline check with
  no model, bare base64 takes content rules from 12/23 to 2/23, the same as homoglyphs. Against a model
  that can decode, it could be a real evasion.

### Each mutation

Recall on attacks that still succeeded; change from the same bases.

| Mutation | Attack success, runs | Content | Sequence | Behavior | All tiers |
|---|---|---|---|---|---|
| homoglyph | 54/66 = 0.818 | 0/21, -0.526 | 3/21, -0.068 | 9/21, -0.098 | 9/21, -0.414 |
| zero_width | 46/66 = 0.697 | 1/23, -0.519 | 5/23, +0.030 | 8/23, -0.027 | 9/23, -0.421 |
| fullwidth | 30/66 = 0.455 | 5/10, +0.000 | 0/10, +0.000 | 3/10, +0.000 | 8/10, +0.000 |
| split_chunks | 8/66 = 0.121 | 1/3, +0.000 | 0/3, +0.000 | 1/3, +0.000 | 2/3, +0.000 |
| base64_bare | 0/66 = 0.000 | null | null | null | null |
| base64_decode | 0/66 = 0.000 | null | null | null | null |

Pooled attack success was 138/396 = 0.348. The two mutations that hurt detection most are also the two
that hurt the attack least, which is what makes them worth an attacker's time.

Fullwidth is the useful contrast. Content rules normalize text with NFKC before matching, NFKC folds
fullwidth characters and does not fold lookalikes from other scripts or remove zero-width marks, and
content recall under fullwidth did not change. That points at a cheap repair for the zero-width
case, untested here, because no rule was changed after results existed.

The fullwidth change has an interval of [+0.000, +0.000]. An interval that narrow means each surviving
attack behaved like its base, not that the change is known to be zero. Split_chunks rests on 3 traces.

### Attack variants

Structural variants (indirect instruction, retrieval poisoning, tool indirection, multi-stage)
succeeded in 12/48 = 0.250 runs and left 5 succeeded traces in 4 groups. They compare different
attacks, not a mutated attack with its base, so they are reported and not read as a paired change.
Multi-stage attacks succeeded in 0/12 runs.

### With guardrails on

Guardrails stopped almost everything before detection mattered: payload mutations succeeded in
2/395 = 0.005 runs, leaving 1 trace to score. There is too little there to read a tier result from.

## The combined system on clean attacks

On unmutated held-out attacks, all tiers together caught 20/28 = 0.714 [0.529, 0.847] of successful
attacks, with a false positive rate of 1/38 = 0.026 [0.005, 0.135] and precision of
20/21 = 0.952 [0.773, 0.992]. The denominator is attacks that worked; another 46 traces were attempts
that failed, and they are in neither rate.

These figures pool both guardrail arms, so the 38 benign traces are 19 benign groups run twice, and the
interval treats them as independent. With guardrails off, recall is 20/26 = 0.769 and the false positive
rate is 1/19 = 0.053 [0.009, 0.246].

This figure and the 39/48 above are different populations. Bases for mutation were chosen because
they succeeded, so do not subtract one mutated figure from 0.714. The paired change is the comparison
to quote.

### Which tier is best on clean attacks

| Tier | Recall | FPR |
|---|---|---|
| content | 12/28 = 0.429 [0.265, 0.609] | 0/38 = 0.000 [0.000, 0.092] |
| behavior | 12/28 = 0.429 [0.265, 0.609] | 0/38 = 0.000 [0.000, 0.092] |
| sequence | 6/28 = 0.214 [0.102, 0.395] | 1/38 = 0.026 [0.005, 0.135] |

Content and behavior tie, and they catch mostly different attacks: 8 traces by content only, 8 by
behavior only, 4 by both and 8 by neither. That is why the combination beats either one. The paired
difference between them is +0.000 [-0.333, +0.300], so this data cannot separate them. Content beats
sequence by +0.214 [+0.037, +0.414]. Sequence against behavior is -0.214 [-0.462, +0.036].

Per class, recall ranges from 0/3 on AC01 to 5/5 on AC07, every class is small-N, and those figures
are in [results-baseline.md](results-baseline.md).

## Individual rules are weak

Pooled over clean or mutated attacks, no single rule clears the registered bar of 0.5 recall at 0.05
FPR. The
best on clean attacks is ADG-0012 at 7/28 = 0.250 [0.127, 0.434], and on payload mutations the same rule
at 12/57 = 0.211. The per-technique table in [coverage.md](coverage.md) therefore reads as it does. The
bar was fixed before any held-out result and has not moved. It tests one rule standing alone, which is a
strict question, and the tier and combined figures above are the better description of the system.

Part of this is the denominator. A rule's recall here is over all succeeded attacks, including ones it
was never aimed at. On the attacks of its own technique, ADG-0014 scores 4/4, and ADG-0006 scores 2/2 on
three of its four techniques and 2/6 on ASI01, on very few traces. It cuts both ways: ADG-0012, the best
rule overall, scores 0/13 on its own AML.T0053 attacks, so its recall comes from elsewhere.

Attack variants read differently on that table, with two rules at 3/5. That is 5 traces, too few to mean
anything, and [coverage.md](coverage.md) flags it.

## What gaps remain

- **Classes nothing caught.** Class descriptions come from the source lab's threat model. On clean
  attacks all tiers scored 0/3 on AC01 (tool use outside an
  allowlist), 0/4 on AC04 (system prompt and hidden context leak) and 0/1 on AC06 (parameter
  manipulation).
- **Rules that never fired on a success.** ADG-0004, ADG-0007, ADG-0008 and ADG-0011 scored 0/28.
  ADG-0008 also produced the one false positive.
- **Techniques with no rule.** Attacks in the corpus exercise IDs that no rule maps to, including
  system prompt extraction. They are listed in
  [coverage.md](coverage.md#attacked-with-no-rule-mapped), as the source threat model writes them, and
  [mappings.md](mappings.md) says how far those were checked.
- **Sequence depends on provenance.** Sequence rules follow content references built from verbatim
  overlap. Tier recall is 6/28 at K=16 and K=24 and 2/28 at K=48. A real deployment would need
  provenance that survives rewriting.
- **Exports are untested on any SIEM.** Rules convert only where the target can state the same test.
  Many do not convert, and those that do assume an ingest pipeline nobody has built. See
  [export.md](export.md).

## Attacks that never worked

AC03 (tool chaining), AC09 (indirect injection through a tool result) and AC10 (exfiltration through
tool arguments) never succeeded at baseline against this model. Each has a single variant group, so that
is thin evidence. They are excluded from recall denominators, and there is nothing to report about
detecting them. AC06 succeeded in only 2 of 14 groups.

Do not read this as those attacks being harmless. Only one model ran, so this cannot separate the model
from the scenario design; [dataset.md](dataset.md) notes one way the design itself limits AC10. Another
model could turn these classes on. It also means this study says nothing about detecting those classes
when they succeed, and two mapped techniques have no successful attacks to detect.

## What did not work

- Keyword rules as a primary control, against an attacker who can change characters.
- Four of the 14 rules, which caught nothing on clean attacks.
- Seeding some classes to the planned size: AC06 stayed low-success and AC12A underpowered, and they
  were reported as such rather than padded.
- A clean separation of the split: 20 of 20 succeeded held-out groups have a parent, sibling or seeded
  child in the dev split, so these rules were written against close relatives of what they were scored
  on. Clean recall may be inflated. The registered set-asides do not show that: all tiers read 11/12 and
  8/9 with two kinds of relative removed. But those rows rest on few traces, and with every relative
  removed, in a row added after scoring, no group is left to test on.
