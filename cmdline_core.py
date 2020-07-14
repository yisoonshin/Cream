#!/usr/bin/env python3


import sys
import os
import pandas as pd
import seaborn as sns


# Take the user-supplied relative path and read the file as a Pandas DataFrame.
def file_to_df(path):
    try:
        # Read csv to Pandas DataFrame object
        df = pd.read_csv(path)
        return df
    # Wrong path check
    except FileNotFoundError:
        print('We could not find or read your file.')
        print('Please check your relative path.')
        # Exit script
        sys.exit()


# Select columns by index number (reduce spelling errors).
def columns_picker(cols_lst):
    metric = cols_lst[int(input('Please select the index number of the metric field:'))]
    indicator = cols_lst[int(input('Please select the index number of the malicious event indicator field:'))]
    print(f'''You will be placing a threshold on \"{metric}\"
and the malicious event indicator is \"{indicator}\".
''')
    return metric, indicator


# Parse dataset for normal vs malicious observations.
# Split into two separate lists.
def classification_split(dataframe, metric_col, indicator_col):
    # Filter for True (1) indicators of malicious activity and select the metric column.
    malicious = dataframe.loc[dataframe[indicator_col] == 1, metric_col].\
        copy().reset_index(drop=True)

    # Filter for 0 to get normal traffic.
    normal = dataframe.loc[dataframe[indicator_col] == 0, metric_col]. \
        copy().reset_index(drop=True)

    # Use pandas.Series methods to calculate stats.
    summary_stats = {
        'normal': {
            'mean': normal.mean(),
            'stddev': normal.std(),
            'median': normal.median()
        },
        'malicious': {
            'mean': malicious.mean(),
            'stddev': malicious.std(),
            'median': malicious.median()
        }
    }
    return summary_stats


# Threshold-generating utility
def threshold_calc(mean, stddev, multiplier):
    return mean + (stddev * multiplier)


def main():
    if "-q" not in sys.argv[1:]:
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
    CREAM get the money, dollar dollar bill, y'all"
    - Wu-Tang Clan 
    
    Welcome to CREAM! 
    
    This tool is meant to help security analysts use threshold-based 
    anomaly detection in a more data-driven way. Our goal is to help you
    catch the majority* of malicious outliers without wasting time on
    false positives, ultimately saving the business more $$$.
    
    * As with any tool, use with caution - a good threshold is not
    a license to "set it and forget it"!
    ''')

    print('''Please select the CSV dataset you\'d like to use.
The dataset should contain these columns:
    - metric to apply threshold to
    - indicator of event to detect (e.g. malicious activity)
        - Please label this as 1 or 0 (true or false); 
        This will not work otherwise!
''')

    file_path = input('Enter the path of your dataset:')
    imported_data = file_to_df(file_path)

    print(f'''\nGreat! Here is a preview of your data:
Imported fields:''')
    # List headers by column index.
    cols = list(imported_data.columns)
    for index in range(len(cols)):
        print(f'{index}: {cols[index]}')
    print(f'Number of records: {len(imported_data.index)}\n')
    # Preview the DataFrame
    print(imported_data.head(), '\n')

    # Prompt for the metric and source of truth.
    metric_col, indicator_col = columns_picker(cols)
    # User self-validation.
    col_check = input('Can you confirm if this is correct? (y/n)').lower()
    while col_check != 'y':
        metric_col, indicator_col = columns_picker(cols)
        col_check = input('Can you confirm if this is correct? (y/n)').lower()
    else:
        print('''\nGreat! Thanks for your patience.
Generating summary stats now..\n''')

    # Generate summary stats.
    data_summary = classification_split(imported_data, metric_col, indicator_col)
    print(f'''Normal vs Malicious Summary (metric = {metric_col}):
Normal:
-----------------------------
Average: {round(data_summary['normal']['mean'],2)}
Standard Deviation: {round(data_summary['normal']['stddev'],2)}

Malicious:
-----------------------------
Average: {round(data_summary['malicious']['mean'],2)}
Standard Deviation: {round(data_summary['malicious']['stddev'],2)}
''')
    # Insights and advisories
    if data_summary['normal']['mean'] >= (data_summary['normal']['median'] * 1.1):
        print(f'''You may want to be cautious as your normal traffic\'s {metric_col} 
has a long tail towards high values. The median is {round(data_summary['normal']['median'],2)} 
compared to {round(data_summary['normal']['mean'],2)} for the average.''')

    if data_summary['malicious']['mean'] < threshold_calc(data_summary['normal']['mean'],
                                                          data_summary['normal']['stddev'],2):
        print(f'''Warning: you may find it difficult to avoid false positives as the average
{metric_col} for malicious traffic is under the 95th percentile of the normal traffic.''')


if __name__ == "__main__":
    main()
