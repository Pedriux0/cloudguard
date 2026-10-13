# ============================================================
# demo.tape - the scripted session behind docs/demo.gif
# ------------------------------------------------------------
# Re-render after changing the tool (see docs/vhs.Dockerfile):
#   docker build -t cloudguard-vhs -f docs/vhs.Dockerfile .
#   docker run --rm -v "$PWD:/vhs" cloudguard-vhs docs/demo.tape
# Runs demo mode only: a fake AWS account (moto), no real calls.
# ============================================================

Output docs/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1280
Set Height 820
Set Padding 20
Set Theme "Builtin Dark"
Set TypingSpeed 60ms
Set WaitTimeout 90s

# Setup the viewer doesn't need to see. The demo MFA code is random
# on every run; a recording can't read the screen, so it's fixed here.
Hide
Type "export CLOUDGUARD_DEMO_CODE=424242 PS1='$ '" Enter
Type "alias cloudguard='python3 -m cloudguard'" Enter
Type "clear" Enter
Show

# 1. Start locked: nothing is shown until MFA succeeds.
Type "cloudguard --demo" Sleep 400ms Enter
Wait+Screen /MFA code:/
Sleep 2.5s

# 2. The code is typed into a hidden prompt (nothing is echoed).
Type "424242" Sleep 500ms Enter
Wait+Screen /cloudguard \[/
Sleep 2s

# 3. Run every check: worst findings first.
Type "audit" Sleep 400ms Enter
Wait+Screen /for details and fixes/
Sleep 6s

# 4. Details and the fix for one finding.
Type "show S3-03" Sleep 400ms Enter
Sleep 5s

# 5. Lock: screen and scrollback wiped, keys dropped, MFA asked again.
Type "lock" Sleep 400ms Enter
Wait+Screen /MFA code:/
Sleep 3.5s

Type "quit" Sleep 300ms Enter
Sleep 2s
