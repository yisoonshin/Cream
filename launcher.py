#!/usr/bin/env python3


import sys
import init
import creamery


def main():
    # Newcomer's intro
    if '-q' not in sys.argv[1:]:
        # Ensure dependencies are met
        init.check_dependencies()
        init.title_card()
    creamery.main()


if __name__ == '__main__':
    main()
