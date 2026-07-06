"""Entry point for ``python -m fimap``."""

import sys


def main():
    from __init__ import __version__  # noqa: F811
    print(f"fimap v{__version__}")
    print("CLI not yet implemented. Use -h for help.")
    sys.exit(0)


if __name__ == "__main__":
    main()
