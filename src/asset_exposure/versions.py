"""
Version comparison for matching installed software against NVD ranges.

Software versions are not uniformly formatted ("2.4.58", "9.6p1",
"8.0.36-0ubuntu0.24.04.1"), so a tolerant comparison is used:
numeric runs compare as numbers, letter runs as text, and a longer
version that extends a shorter one is newer (9.6p1 > 9.6).

Known limitation: pre-release tags ("2.0rc1") sort after the release.
"""

import re

import pandas as pd

TOKEN = re.compile(r"\d+|[a-z]+")

# Distribution packaging suffixes that are not part of the upstream
# version (e.g. "9.6p1 Ubuntu 3ubuntu13.5", "8.0.36-0ubuntu0.24.04.1")
DISTRO_SUFFIX = re.compile(r"[\s\-+~](?:ubuntu|debian|deb|el\d|fc\d|\d+ubuntu).*$", re.I)


def clean_version(version):
    if version is None or pd.isna(version):
        return None

    version = DISTRO_SUFFIX.sub("", str(version).strip().lower())
    version = version.split()[0] if version else ""

    return version or None


def version_key(version):
    # Numbers sort above letters at the same position, so "9.6.1" > "9.6p1"
    return tuple(
        (1, int(token)) if token.isdigit() else (0, token)
        for token in TOKEN.findall(str(version).lower())
    )


def compare(a, b):
    ka, kb = version_key(a), version_key(b)
    return (ka > kb) - (ka < kb)


def is_set(value):
    return value is not None and not pd.isna(value) and value not in ("", "*", "-")


def version_matches(installed, row):
    """
    True if the installed version falls inside one NVD cpeMatch entry.

    row: mapping with version, update and version_{start,end}_{including,excluding}
    """
    nvd_version = row["version"]

    # A specific version listed (e.g. openssh 9.6 update p1)
    if is_set(nvd_version):
        listed = str(nvd_version)
        if is_set(row["update"]):
            listed += str(row["update"])
        return compare(installed, listed) == 0

    # "*" with a range: check each bound that is present
    if is_set(row["version_start_including"]) and compare(installed, row["version_start_including"]) < 0:
        return False
    if is_set(row["version_start_excluding"]) and compare(installed, row["version_start_excluding"]) <= 0:
        return False
    if is_set(row["version_end_including"]) and compare(installed, row["version_end_including"]) > 0:
        return False
    if is_set(row["version_end_excluding"]) and compare(installed, row["version_end_excluding"]) >= 0:
        return False

    return True


def next_version(version):
    """The release after an inclusive upper bound: "8.0.39" -> "8.0.40"."""
    match = list(re.finditer(r"\d+", str(version)))
    if not match:
        return None
    last = match[-1]
    return version[:last.start()] + str(int(last.group()) + 1) + version[last.end():]


def fixed_version(installed, row):
    """
    First version that fixes one NVD cpeMatch range the installed version
    falls in: the exclusive upper bound, or the release after an inclusive
    one. None when NVD gives no upper bound (no fix recorded).
    """
    if is_set(row["version_end_excluding"]):
        return str(row["version_end_excluding"])
    if is_set(row["version_end_including"]):
        return next_version(str(row["version_end_including"]))
    return None


def has_bounds(row):
    return is_set(row["version"]) or any(
        is_set(row[c]) for c in ["version_start_including", "version_start_excluding",
                                 "version_end_including", "version_end_excluding"]
    )
