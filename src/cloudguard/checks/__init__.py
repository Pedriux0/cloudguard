"""
checks/ - every security rule cloudguard runs
=============================================

ALL_CHECKS is the master list. To add a new check:
    1. Write it in one of the files below (or a new file)
    2. Add it to that file's CHECKS list
    3. Add any new AWS calls to guard.py AND iam-policy.json
       (a test fails if those two don't match)
"""

from cloudguard.checks import iam, logging_checks, network, s3

ALL_CHECKS = [
    *iam.CHECKS,
    *s3.CHECKS,
    *network.CHECKS,
    *logging_checks.CHECKS,
]
