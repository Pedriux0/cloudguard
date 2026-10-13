"""Allows `python -m cloudguard` as well as the `cloudguard` command."""

import sys

from cloudguard.cli import main

sys.exit(main())
