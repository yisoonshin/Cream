#!/usr/bin/env python3


import sys
import subprocess
import time


req_check = [
    'pandas',
    'numpy',
    'matplotlib',
    'seaborn',
    'bokeh'
]


def mod_check(lst):
    for module in lst:
        try:
            print(f'Checking for {module}:')
            if subprocess.check_call([sys.executable, '-m', 'pip', 'show', module],
                                     stdout=subprocess.DEVNULL) == 0:
                print(f'Found!')
        except subprocess.CalledProcessError:
            if input('Can we install it? (y/n): ') == 'y':
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', module])
            else:
                print('What a shame, maybe next time.')
                sys.exit()


def check_dependencies():
    if input('Want to check for the necessary modules? (y/n): ').lower() == 'y':
        mod_check(req_check)
        print('\"It\'s all good, baby baby\" - Notorious B.I.G')


def title_card():
    print('''
      ______      _______       ________       ______       __       __ 
     /      \    /       \     /        |     /      \     /  \     /  |
    /$$$$$$  |   $$$$$$$  |    $$$$$$$$/     /$$$$$$  |    $$  \   /$$ |
    $$ |  $$/    $$ |__$$ |    $$ |__        $$ |__$$ |    $$$  \ /$$$ |
    $$ |         $$    $$<     $$    |       $$    $$ |    $$$$  /$$$$ |
    $$ |   __    $$$$$$$  |    $$$$$/        $$$$$$$$ |    $$ $$ $$/$$ |
    $$ \__/  |__ $$ |  $$ | __ $$ |_____  __ $$ |  $$ | __ $$ |$$$/ $$ |
    $$    $$//  |$$ |  $$ |/  |$$       |/  |$$ |  $$ |/  |$$ | $/  $$ |
     $$$$$$/ $$/ $$/   $$/ $$/ $$$$$$$$/ $$/ $$/   $$/ $$/ $$/      $$/ 

    "Cash rules everything around me
    CREAM get the money, dolla dolla bill, y'all"
    - Wu-Tang Clan''')
    # Add delay
    time.sleep(1)
    print('''
    Blue Team problems are ultimately business problems.
    Is the juice worth the squeeze? 

    This tool is meant to help security analysts use threshold-based 
    anomaly detection in a more data-driven way, catching the majority*
    of malicious outliers while minimizing time wasted on false positives.

    Because time is $$$.

    * As with any tool, use with caution;
    a data-driven threshold is not a license to "set it and forget it"!

    Tip: launch with the "-q" flag to skip this prompt.
    ''')
    time.sleep(1)

