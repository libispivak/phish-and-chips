"""Command line: python -m scorer path/to/email.eml [more.eml ...]"""

import sys

from .engine import score_email

ICONS = {"safe": "OK ", "suspicious": "?? ", "malicious": "!! "}


def main(paths):
    for path in paths:
        with open(path, "rb") as handle:
            result = score_email(handle.read())
        print(f"\n{ICONS[result['verdict']]}{result['verdict'].upper():<10} {result['score']:>3}/100  {path}")
        for signal in result["signals"]:
            print(f"     [{signal['id']}] +{signal['points']:<2} {signal['title']}: {signal['detail']}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python -m scorer EMAIL.eml [EMAIL.eml ...]")
    main(sys.argv[1:])
