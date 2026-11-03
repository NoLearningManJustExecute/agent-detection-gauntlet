# Demo script and recording guide

A two-minute walk through the result, with the script and the checklist for recording one. Nothing in the
script below needs a model or reads a held-out trace.

## Published recording

The GIF in the README is a separate, shorter take, made from [assets/demo.tape](assets/demo.tape). It needs
no model, but it does read held-out traces. `gauntlet evasion verify` loads them for its integrity checks and
writes no log row. `gauntlet evasion score --check` with `GAUNTLET_SCORING_HELDOUT=1` re-scores them with the
frozen rules and compares the answer to the committed results. Each such run appends a row to
[heldout-log.md](heldout-log.md). The rows from making this recording are committed there. No rule changed.

Run locally, as in the clip, `evasion verify` checks the rules against the registration. The comparison with
the registration as first committed runs in CI.

The table at the end of the clip comes from [demo/evasion_table.py](demo/evasion_table.py), which only prints
numbers from `results/evasion/evasion.json`.

## Before recording

A recording can leak a username or a path as pixels, and no text scan will see that.

- Use a fresh clone in a short neutral folder, such as a temporary directory.
- Set a clean prompt with no username, host or path: `PS1='$ '` in bash, or
  `function prompt { '$ ' }` in PowerShell.
- Clear the terminal scrollback, and use a terminal profile with a neutral title.
- Capture the terminal pane or one browser viewport, not the whole screen, so no window title, taskbar,
  notification or browser profile name shows.
- Open the dashboard in a clean browser profile with no signed-in avatar or bookmarks bar.

## Script

**1. The question (15 seconds).** Show the top of the README: which detections stay effective when
attackers try to evade them?

**2. The rules are frozen (20 seconds).** They were hashed and registered before any held-out score.

```sh
gauntlet validate-rules rules
gauntlet validation verify
```

Say: 14 rules, three tiers. The warnings are one mapping that did not match the current ATLAS release,
and they are left visible on purpose.

**3. The result (45 seconds).** Open `docs/dashboard.html`, at the bar chart and then the table.

Say: under payload mutation, content recall falls by 0.398, from 25/48 to 7/57, while sequence and
behavior show no measurable drop. Homoglyphs take content to 0/21. Base64 is not an evasion here: 0/66
runs succeeded, because the model could not act on it.

**4. The honest part (20 seconds).** Stay on the dashboard, at the clean table and per-rule rows.

Say: together the tiers catch 20/28 clean attacks at 1/38 false positives, but pooled over clean or mutated attacks
no single rule clears the bar we registered, and holding is not catching: the combined system still drops.

**5. Why to trust it (20 seconds).**

```sh
gauntlet publish numbers
gauntlet coverage build --check
```

Say: CI fails on a published fraction or rate that no committed JSON holds. Finish on
`docs/limitations.md`.

## Checklist

- [ ] Prompt shows no username, host or path in any frame
- [ ] Every frame checked for window titles, notifications and browser profile names
- [ ] Numbers spoken match the dashboard
- [ ] Limitations mentioned: one local model, one author, relatives across the split, no live SIEM
- [ ] Video metadata checked and stripped
- [ ] Reviewed by the owner before it goes anywhere
