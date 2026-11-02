# Synthetic fixtures

Everything in this directory is synthetic. It was written by hand to exercise the pipeline,
and every label carries `source: synthetic`. No trace here came from a real agent or a real
model, and no number computed from these files is a finding.

- `traces/`: one JSONL file per trace, named by trace id. Trace ids are neutral (`syn-NNNN`)
  so the ground truth cannot be read from the trace itself.
- `labels.jsonl`: ground truth for every trace, kept apart from the traces.

| Trace | Split | Shape |
|---|---|---|
| syn-0001 | dev | untrusted retrieval whose content reaches a send_email call |
| syn-0002 | dev | trusted retrieval followed by a legitimate send_email |
| syn-0003 | dev | untrusted retrieval, then a send_email built only from the user prompt |
| syn-0004 | heldout | untrusted retrieval whose content reaches an http_post call |
| syn-0005 | heldout | trusted retrieval followed by a team post |
| syn-0006 | heldout | untrusted retrieval reaches send_email, a guardrail blocks it |
| syn-0007 | heldout | untrusted retrieval reaches upload_file, provenance missing on the model request |
| syn-0008 | heldout | untrusted retrieval and an unrelated team post |
| syn-0009 | heldout | user deliberately forwards an untrusted public article |
| syn-0010 | dev | untrusted read, then a secret read, then a send_email |

The dev traces are fixtures named by rules. syn-0010 exists because the corpus dev split holds
no successful trace with that shape; ADG-0007 and ADG-0008 name it, and no result depends on it. The heldout traces exist so the
metrics stage has every outcome bucket to count: a hit, a miss, a false alarm, true
negatives and a failed attack.
