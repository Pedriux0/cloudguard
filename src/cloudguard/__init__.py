"""
cloudguard - a read-only, MFA-protected AWS security audit tool.

Start reading here:
    cli.py      -> where the program starts
    session.py  -> the locked/unlocked secure shell
    auth.py     -> MFA login and the read-only role
    guard.py    -> the code-level "no writes allowed" filter
    checks/     -> the actual security rules
"""

__version__ = "0.1.0"
