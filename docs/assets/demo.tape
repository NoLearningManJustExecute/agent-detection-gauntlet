# Records docs/assets/demo.gif. No model runs: this re-scores the committed traces with the frozen rules.
# Run from the repository root with the virtual environment in .venv:
#   vhs docs/assets/demo.tape
# The re-score appends a row to docs/heldout-log.md.

Output docs/assets/demo.gif

Set Shell "powershell"
Set FontSize 14
Set Width 1060
Set Height 680
Set Padding 18
Set Theme "Dracula"
Set TypingSpeed 35ms
Set Framerate 12
Set WaitTimeout 120s

# Put the venv on PATH and use a plain prompt, so no local path shows on screen.
Hide
Type `Remove-Module PSReadLine -ErrorAction SilentlyContinue; $env:PATH = (Resolve-Path .venv\Scripts).Path + ';' + $env:PATH; function prompt { '$ ' }; cls`
Enter
Sleep 2s
Show

Type "# The rules are frozen. Registration, inputs and results must agree."
Enter
Sleep 800ms
Type "gauntlet evasion verify"
Sleep 600ms
Enter
Wait+Screen /rules and results agree/
Sleep 3s

Type "# Re-score the clean and mutated traces. The answer must match the committed results byte for byte."
Enter
Sleep 800ms
Type "$env:GAUNTLET_SCORING_HELDOUT = '1'; gauntlet evasion score --check"
Sleep 600ms
Enter
Wait+Screen /byte-identical/
Sleep 3s

Type "cls"
Enter
Sleep 300ms
Type "python docs/demo/evasion_table.py"
Sleep 600ms
Enter
Wait+Screen /all_tiers +[-+]/
Sleep 14s
