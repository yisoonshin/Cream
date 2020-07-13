#!/usr/bin/env python3


import os
import pandas as pd


# Take the user-supplied relative path and read the file as a Pandas DataFrame.
def file_to_df(path):
    try:
        df = pd.read_csv(path)
        return df
    except ValueError:
        print('We could not find or read your file.')
        print('Please check your relative path.')


def main():
    print('''Welcome! Please select the CSV dataset you\'d like to use.
The dataset should contain these columns:
    - metric to apply threshold to
    - indicator of event to detect (e.g. malicious activity)
''')
    file_path = input('Enter the path of your dataset:')
    imported_data = file_to_df(file_path)

    print(f'''Great! Here is a preview of your data:
Imported fields: {list(imported_data.columns)}
Number of records: {len(imported_data.index)}
    ''')
    print(imported_data.head())


if __name__ == "__main__":
    main()
