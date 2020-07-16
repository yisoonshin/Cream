#!/usr/bin/env python3


import sys
import os
import pandas as pd
import numpy as np
from matplotlib import pyplot as plt
import matplotlib.ticker as mtick
import seaborn as sns
import time

from bokeh.io import output_notebook, output_file, show
from bokeh.plotting import figure
from bokeh.models import Div, Arrow, NormalHead, Label, Span, Legend


# Declare styling for data viz
normal_color = '#b3e6ff'
malicious_color = '#800000'
fp_color = '#c2c2d6'
fn_color = '#ff0000'
precision_color = '#e60000'
recall_color = '#33ccff'
f1_color = '#6600cc'
weighted_fn_color = '#ff9900'
total_weighted_color = '#00cc44'


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
    metric = cols_lst[int(input('Please select the index number of the metric field: '))]
    indicator = cols_lst[int(input('Please select the index number of the malicious event indicator field: '))]
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
            'median': normal.median(),
            'count': normal.size
        },
        'malicious': {
            'mean': malicious.mean(),
            'stddev': malicious.std(),
            'median': malicious.median(),
            'count': malicious.size
        }
    }
    return malicious, normal, summary_stats


# Threshold-generating utility
def threshold_calc(mean, stddev, multiplier):
    return mean + (stddev * multiplier)


# Populate app and project folders in home directory
def make_folder():
    folder_name = input('Pick a name for the project folder: ')
    home = os.path.expanduser('~')
    # Check if there's an app folder
    app_path = os.path.join(home, 'cream')
    if not os.path.isdir(app_path):
        os.mkdir(app_path)
        print(f'Created app folder at: {app_path}')
    session_folder = os.path.join(app_path, folder_name)
    if not os.path.isdir(session_folder):
        os.mkdir(session_folder)
        print(f'Created project folder at: {session_folder}')
    else:
        print('This folder already exists.')
    return session_folder


# Generate confusion matrix and accuracy scores based on a threshold
def confusion_matrix(mal_series, norm_series, threshold):
    mal_lst = mal_series.tolist()
    norm_lst = norm_series.tolist()
    true_positives = len([i for i in mal_lst if i >= threshold])
    false_positives = len([i for i in norm_lst if i >= threshold])
    true_negatives = len(norm_lst) - false_positives
    false_negatives = len(mal_lst) - true_positives

    precision = true_positives / (true_positives + false_positives)
    recall = true_positives / (true_positives + false_negatives)
    f1_score = 2 * (precision * recall) / (precision + recall)

    outcome_dict = {
        'TP': true_positives,
        'FP': false_positives,
        'TN': true_negatives,
        'FN': false_negatives,
        'precision': precision,
        'recall': recall,
        'f1_score': f1_score
    }

    return outcome_dict


# Let's iterate over a list of multipliers and generate a DataFrame of all the results
def monte_carlo(mal_series, norm_series, norm_mean, norm_stddev, mult_lst):
    evaluations = {}
    for mult in mult_lst:
        threshold = threshold_calc(norm_mean, norm_stddev, mult)
        evaluations[mult] = confusion_matrix(mal_series, norm_series, threshold)
    eval_df = pd.DataFrame.from_dict(evaluations, orient='index').\
        reset_index().rename(columns={'index': 'multiplier'})
    return eval_df


# Create nuanced optimization based on weighting of FN
def cost_minimization(dataframe, session_folder):
    # Create a separate folder for each ratio input.
    scenario = input('Please choose a name for this scenario: ')
    scenario_folder = os.path.join(session_folder, scenario)
    if not os.path.isdir(scenario_folder):
        os.mkdir(scenario_folder)
        print(f'Created the folder {scenario_folder}.')

    # Ask the user to provide a ratio to weigh FN
    fn_ratio_input = input('How would you weigh false negatives to false positives? (e.g. 2:1): ')
    fn_ratio = float(fn_ratio_input.split(':')[0])

    # Calculate weighted false negatives, then sum with false positives.
    dataframe['weighted_FN'] = dataframe.FN * fn_ratio
    dataframe['total_weighted_errors'] = dataframe.FP + dataframe.weighted_FN

    # Find the first threshold at which TWE is minimized
    w_error_min = dataframe[dataframe.total_weighted_errors == dataframe.total_weighted_errors.min()].head(1)
    w_error_min_mult = w_error_min.head().squeeze()['multiplier']

    time.sleep(1)
    print(f'''\nBased on total weighted errors ({fn_ratio_input} ratio), setting a threshold at {round(w_error_min_mult, 1)} standard deviations 
above the average magnitude might minimize errors based on the context you provided. 

{w_error_min[['multiplier', 'FP', 'weighted_FN', 'total_weighted_errors', 'f1_score']]}

As always, we recommend that you take a look at the outputs to make your own judgement.\n''')

    # Export updated stats.
    dataframe.to_csv(os.path.join(scenario_folder, f'simulation_weighted_results_{scenario}.csv'),
                     index=False)

    # Plot weighted + total errors.
    fig, ax = plt.subplots()
    fig = plt.gcf()
    fig.set_size_inches(9, 6)
    sns.lineplot(x='multiplier', y='FP', data=dataframe, label='false positives', color=fp_color)
    sns.lineplot(x='multiplier', y='FN', data=dataframe, label='false negatives', color=fn_color)
    sns.lineplot(x='multiplier', y='weighted_FN', data=dataframe,
                 label='weighted false negatives', color=weighted_fn_color)
    sns.lineplot(x='multiplier', y='total_weighted_errors', data=dataframe,
                 label='total weighted errors', color=total_weighted_color)
    plt.ylabel('Count')
    plt.xlabel('Multiplier')
    ax.get_yaxis().set_major_formatter(plt.FuncFormatter(lambda x, loc: "{:,}".format(int(x))))
    plt.title(f'Weighted Errors Across Multipliers ({fn_ratio_input} FN:FP Ratio)')
    plt.legend()
    plt.savefig(os.path.join(scenario_folder, f'simulated_weighted_errors_{scenario}.png'))

    # Evaluation Metrics vs Total Weighted Errors
    fig, ax = plt.subplots()
    fig = plt.gcf()
    fig.set_size_inches(9, 6)
    sns.lineplot(x='multiplier', y='precision', data=dataframe, label='precision', color=precision_color)
    sns.lineplot(x='multiplier', y='recall', data=dataframe, label='recall', color=recall_color)
    sns.lineplot(x='multiplier', y='f1_score', data=dataframe, label='f1 score', color=f1_color)
    ax.set_ylabel('Score')
    ax.get_yaxis().set_major_formatter(mtick.PercentFormatter(1.0))
    plt.xlabel('Multiplier')
    ax.legend(loc='upper left')

    # Secondary axis for total weighted errors
    ax2 = ax.twinx()
    sns.lineplot(x='multiplier', y='total_weighted_errors', data=dataframe,
                 label='total weighted errors', color=total_weighted_color)
    ax2.set_ylabel('Total Weighted Errors')
    ax2.get_yaxis().set_major_formatter(plt.FuncFormatter(lambda x, loc: "{:,}".format(int(x))))
    ax2.legend(loc='upper right')

    plt.title(f'Evaluation Metrics vs Total Weighted Errors Across Multiplier Levels ({fn_ratio_input} FN:FP Ratio)')
    plt.savefig(os.path.join(scenario_folder, f'simulated_evaluation_vs_weighted_error_{scenario}.png'))
    print(f'Simulation results have been saved to {scenario_folder}.')


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
    CREAM get the money, dolla dolla bill, y'all"
    - Wu-Tang Clan''')
        # Add delay
        time.sleep(2)
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
        # Add some delay
        time.sleep(1)

    print('''Please select the CSV dataset you\'d like to use.
The dataset should contain these columns:
    - metric to apply threshold to
    - indicator of event to detect (e.g. malicious activity)
        - Please label this as 1 or 0 (true or false); 
        This will not work otherwise!
''')

    file_path = input('Enter the path of your dataset: ')
    imported_data = file_to_df(file_path)

    time.sleep(1)

    print(f'''\nGreat! Here is a preview of your data:
Imported fields:''')
    # List headers by column index.
    cols = list(imported_data.columns)
    for index in range(len(cols)):
        print(f'{index}: {cols[index]}')
    print(f'Number of records: {len(imported_data.index)}\n')
    # Preview the DataFrame
    time.sleep(1)
    print(imported_data.head(), '\n')

    # Prompt for the metric and source of truth.
    time.sleep(1)
    metric_col, indicator_col = columns_picker(cols)
    # User self-validation.
    col_check = input('Can you confirm if this is correct? (y/n): ').lower()
    while col_check != 'y':
        metric_col, indicator_col = columns_picker(cols)
        col_check = input('Can you confirm if this is correct? (y/n): ').lower()
    else:
        print('''\nGreat! Thanks for your patience.
Generating summary stats now..\n''')

    # Generate summary stats.
    time.sleep(1)
    malicious, normal, data_summary = classification_split(imported_data, metric_col, indicator_col)
    norm_mean = data_summary['normal']['mean']
    norm_stddev = data_summary['normal']['stddev']
    norm_count = data_summary['normal']['count']
    mal_mean = data_summary['malicious']['mean']
    mal_stddev = data_summary['malicious']['stddev']
    mal_count = data_summary['malicious']['count']

    print(f'''Normal vs Malicious Summary (metric = {metric_col}):
Normal:
-----------------------------
Observations: {round(data_summary['normal']['count'],2)}
Average: {round(norm_mean,2)}
Standard Deviation: {round(norm_stddev,2)}

Malicious:
-----------------------------
Observations: {round(data_summary['malicious']['count'],2)}
Average: {round(mal_mean,2)}
Standard Deviation: {round(mal_stddev,2)}
''')
    # Insights and advisories
    # Provide the accuracy metrics of a generic threshold at avg + 3 std deviations
    generic_threshold = confusion_matrix(malicious, normal, threshold_calc(norm_mean, norm_stddev, 3))

    time.sleep(1)
    print(f'''A threshold at (average + 3x standard deviations) {metric_col} would result in:
    - True Positives (correctly identified malicious events: {generic_threshold['TP']:,}
    - False Positives (wrongly identified normal events: {generic_threshold['FP']:,}
    - True Negatives (correctly identified normal events: {generic_threshold['TN']:,}
    - False Negatives (wrongly identified malicious events: {generic_threshold['FN']:,}

    Accuracy Metrics:
    - Precision (what % of events above threshold are actually malicious): {round(generic_threshold['precision'] * 100, 1)}%
    - Recall (what % of malicious events did we catch): {round(generic_threshold['recall'] * 100, 1)}%
    - F1 Score (blends precision and recall): {round(generic_threshold['f1_score'] * 100, 1)}%''')

    # Distribution skew
    if norm_mean >= (data_summary['normal']['median'] * 1.1):
        time.sleep(1)
        print(f'''\nYou may want to be cautious as your normal traffic\'s {metric_col} 
has a long tail towards high values. The median is {round(data_summary['normal']['median'],2)} 
compared to {round(norm_mean,2)} for the average.''')

    if mal_mean < threshold_calc(norm_mean, norm_stddev, 2):
        time.sleep(1)
        print(f'''\nWarning: you may find it difficult to avoid false positives as the average
{metric_col} for malicious traffic is under the 95th percentile of the normal traffic.''')

    # Prompt if we should generate exploratory data viz for the user.
    time.sleep(1)
    exploratory_option = input('\nWould you like to export exploratory data visualizations? (y/n): ').lower()
    if exploratory_option == 'y':
        # auto_open = input('Should I open the files automatically in your browser? (y/n): ').lower()
        print('We will create a folder to save these files in.')
        session_folder = make_folder()
        time.sleep(1)
        print('Generating visualizations..')

        # Export a high-level histogram of data distribution
        fig, ax = plt.subplots()
        fig = plt.gcf()
        fig.set_size_inches(9, 6)
        sns.distplot(imported_data.loc[imported_data[indicator_col] == 0, metric_col],
                     kde=False, bins=100, label='Normal', color=normal_color)
        sns.distplot(imported_data.loc[imported_data[indicator_col] == 1, metric_col],
                     kde=False, bins=100, label='Malicious', color=malicious_color)
        plt.xlabel('Magnitude')
        plt.ylabel('Observations')
        plt.title('Normal vs Malicious Activity Distribution')
        ax.get_xaxis().set_major_formatter(plt.FuncFormatter(lambda x, loc: "{:,}".format(int(x))))
        ax.get_yaxis().set_major_formatter(plt.FuncFormatter(lambda x, loc: "{:,}".format(int(x))))
        # Annotate where malicious activity lies in case it's really small relative to normal traffic
        plt.annotate('Malicious Activity', xy=(mal_mean, 0),
                     xytext=(mal_mean, data_summary['malicious']['count'] * .50),
                     color='black', arrowprops=dict(width=.25, headlength=3, headwidth=3))
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(session_folder, 'exploratory_data_histogram.png'))

        # Zoomed in w/generic 3 std dev threshold.
        fig, ax = plt.subplots()
        fig = plt.gcf()
        fig.set_size_inches(9, 6)
        sns.distplot(imported_data.loc[imported_data[indicator_col] == 0, metric_col],
                     kde=False, bins=100, label='Normal', color=normal_color)
        sns.distplot(imported_data.loc[imported_data[indicator_col] == 1, metric_col],
                     kde=False, bins=100, label='Malicious', color=malicious_color)
        plt.xlabel('Magnitude')
        plt.ylabel('Observations')
        plt.title('Normal vs Malicious Activity Distribution (Zoomed In w/Generic Threshold')
        ax.get_xaxis().set_major_formatter(plt.FuncFormatter(lambda x, loc: "{:,}".format(int(x))))
        ax.get_yaxis().set_major_formatter(plt.FuncFormatter(lambda x, loc: "{:,}".format(int(x))))
        plt.xlim(threshold_calc(norm_mean, norm_stddev, 2.5), threshold_calc(mal_mean, mal_stddev, 4))
        plt.ylim(0, 300 * .20)
        plt.axvline(x=threshold_calc(norm_mean, norm_stddev, 3),
                    color='k', linestyle='dashed', linewidth=1, label='3 std dev threshold')
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(session_folder, 'exploratory_data_focused_histogram.png'))

        # % of total distribution for context
        fig, ax = plt.subplots()
        fig = plt.gcf()
        fig.set_size_inches(9, 6)
        sns.distplot(imported_data.loc[imported_data[indicator_col] == 0, metric_col],
                     kde=True, bins=100, label='Normal', color=normal_color)
        sns.distplot(imported_data.loc[imported_data[indicator_col] == 1, metric_col],
                     kde=True, bins=100, label='Malicious', color=malicious_color)
        plt.xlabel('Magnitude')
        plt.ylabel('% of Category Observations')
        plt.title('Normal vs Malicious Activity Distribution (% of Group Total)')
        ax.get_xaxis().set_major_formatter(plt.FuncFormatter(lambda x, loc: "{:,}".format(int(x))))
        ax.get_yaxis().set_major_formatter(mtick.PercentFormatter(1.0))
        plt.axvline(x=threshold_calc(norm_mean, norm_stddev, 3),
                    color='k', linestyle='dashed', linewidth=1, label='3 std dev threshold')
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(session_folder, 'exploratory_data_probability_density.png'))

        print(f'Exploratory data has been saved to {session_folder}.\n')

    # Let's get to the simulations!
    time.sleep(1)
    print('''Instead of manually experimenting with threshold multipliers, 
let\'s simulate a range of options.\n''')
    # Generate list of multipliers to iterate over
    time.sleep(1)
    mult_start = float(input('Please provide the minimum multiplier you want to start at. We recommend 2: '))
    mult_end = (imported_data[metric_col].max() - data_summary['normal']['mean']) / data_summary['normal']['stddev']
    mult_interval = float(input('Please provide the desired gap between multiplier options: '))
    # range() only allows integers, let's manually populate a list
    multipliers = []
    mult_counter = mult_start
    while mult_counter < mult_end:
        multipliers.append(round(mult_counter,2))
        mult_counter += mult_interval
    print('Generating simulations..\n')

    # Run simulations using our multipliers.
    simulations = monte_carlo(malicious, normal, norm_mean, norm_stddev, multipliers)
    print('Done!')
    time.sleep(1)
    # Create session folder if we haven't already.
    if exploratory_option == 'n':
        session_folder = make_folder()
    simulations.to_csv(os.path.join(session_folder, 'simulation_standard_results.csv'), index=False)
    # Find the first threshold with the highest F1 score.
    # This provides a balanced approach between precision and recall.
    f1_max = simulations[simulations.f1_score == simulations.f1_score.max()].head(1)
    f1_max_mult = f1_max.squeeze()['multiplier']
    time.sleep(1)
    print(f'''\nBased on the F1 score metric, setting a threshold at {round(f1_max_mult,1)} standard deviations
above the average magnitude might provide optimal results.\n''')
    time.sleep(1)
    print(f'''{f1_max}

We recommend that you skim the CSV and visualization outputs to sanity check 
results and make your own judgement.
''')

    # False Positives vs False Negatives.
    fig, ax = plt.subplots()
    fig = plt.gcf()
    fig.set_size_inches(9, 6)
    sns.lineplot(x='multiplier', y='FP', data=simulations, label='false positives', color=fp_color)
    sns.lineplot(x='multiplier', y='FN', data=simulations, label='false negatives', color=fn_color)
    plt.ylabel('Count')
    plt.xlabel('Multiplier')
    ax.get_yaxis().set_major_formatter(plt.FuncFormatter(lambda x, loc: "{:,}".format(int(x))))
    plt.title('FP vs FN Across Multipliers')
    plt.legend()
    plt.savefig(os.path.join(session_folder, 'simulated_FP_vs_FN.png'))

    # Evaluation Metrics.
    fig, ax = plt.subplots()
    fig = plt.gcf()
    fig.set_size_inches(9, 6)
    sns.lineplot(x='multiplier', y='precision', data=simulations, label='precision', color=precision_color)
    sns.lineplot(x='multiplier', y='recall', data=simulations, label='recall', color=recall_color)
    sns.lineplot(x='multiplier', y='f1_score', data=simulations, label='f1 score', color=f1_color)
    plt.ylabel('Score')
    plt.xlabel('Multiplier')
    ax.get_yaxis().set_major_formatter(mtick.PercentFormatter(1.0))
    plt.title('Evaluation Metrics Across Multiplier Levels')
    plt.legend(loc='lower center')
    plt.savefig(os.path.join(session_folder, 'simulated_evaluation_metrics.png'))

    print(f'Simulation results have been saved to {session_folder}.\n')

    time.sleep(1)

    print('''Error types differ in impact - in the case of security incidents, a false negative, 
though possibly rarer than false positives, is likely more costly.\n''')

    time.sleep(1)

    print('''For example, downtime suffered from a DDoS attack (lost sales/customers) incurs more 
loss than time wasted chasing a false positive (labor hours)\n''')
    time.sleep(1)

    # Receive a command to perform weighting on FN
    perform_weighting = input('Would you like to try a cost-minimizing approach? (y/n): ').lower()
    while perform_weighting == 'y':
        cost_minimization(simulations, session_folder)
        time.sleep(1)
        perform_weighting = input('''\nPlease check the outputted files.
Would you like to run another scenario? (y/n): ''').lower()


    # Add in Bokeh

    # Summary Stats
    text = f"""
<h1>Normal vs Malicious Summary</h1> 
<i>metric = magnitude</i>

<table style="width:100%,text-align: right">
  <tr>
    <th style="text-align:left">Metric</th>
    <th style="text-align:left">Normal Events</th>
    <th style="text-align:left">Malicious Events</th>
  </tr>
  <tr>
    <td style="text-align:left">Observations</td>
    <td style="text-align:left">{norm_count:,}</td>
    <td style="text-align:left">{mal_count:,}</td>
  </tr>
  <tr>
    <td style="text-align:left">Average</td>
    <td style="text-align:left">{round(norm_mean,2):,}</td>
    <td style="text-align:left">{round(mal_mean,2):,}</td>
  </tr>
  <tr>
    <td style="text-align:left">Standard Deviation</td>
    <td style="text-align:left">{round(norm_stddev,2):,}</td>
    <td style="text-align:left">{round(mal_stddev:,2):,}</td>
  </tr>  
</table>

<p>A threshold at <i>(average + 3x standard deviations)</i> magnitude would result in:</p>
<ul>
    <li>True Positives (correctly identified malicious events: <b>{generic_threshold['TP']:,}</b></li>
    <li>False Positives (wrongly identified normal events: <b>{generic_threshold['FP']:,}</b></li>
    <li>True Negatives (correctly identified normal events: <b>{generic_threshold['TN']:,}</b></li>
    <li>False Negatives (wrongly identified malicious events: <b>{generic_threshold['FN']:,}</b></li>
</ul>
<h3>Accuracy Metrics</h3>
<ul>
    <li>Precision (what % of events above threshold are actually malicious): <b>{round(generic_threshold['precision'] * 100, 1)}</b></li>
    <li>Recall (what % of malicious events did we catch): <b>{round(generic_threshold['recall'] * 100, 1)}</b></li>
    <li>F1 Score (blends precision and recall): <b>{round(generic_threshold['f1_score'] * 100, 1)}</b></li>
</ul>
    """
    stats_div = Div(text=text, width=500, height=200)
    show(stats_div)

    # Let's get the exploratory charts generated

    malicious_hist, malicious_edge = np.histogram(malicious, bins=100)
    mal_hist_df = pd.DataFrame({
        'magnitude': malicious_hist,
        'left': malicious_edge[:-1],
        'right': malicious_edge[1:]
    })

    normal_hist, normal_edge = np.histogram(normal, bins=100)
    norm_hist_df = pd.DataFrame({
        'magnitude': normal_hist,
        'left': normal_edge[:-1],
        'right': normal_edge[1:]
    })

    exploratory = figure(plot_width=900, plot_height=600,
                         title='Magnitude Distribution Across Normal vs Malicious Events',
                         x_axis_label='Magnitude',
                         y_axis_label='Observations'
                         )

    exploratory.quad(bottom=0, top=mal_hist_df.magnitude, left=mal_hist_df.left, right=mal_hist_df.right,
                     legend_label='malicious', fill_color='purple', alpha=.85)
    exploratory.quad(bottom=0, top=norm_hist_df.magnitude, left=norm_hist_df.left, right=norm_hist_df.right,
                     legend_label='normal', fill_color='cyan', alpha=.35)

    exploratory.add_layout(Arrow(end=NormalHead(fill_color='red', size=10),
                                 x_start=mal_mean, y_start=mal_count, x_end=mal_mean, y_end=0))
    arrow_label = Label(x=mal_mean, y=mal_count * 1.2, text='Malicious Events')
    exploratory.add_layout(arrow_label)

    exploratory.legend.location = "top_right"
    show(exploratory)

    # Zoomed in version
    overlap_view = figure(plot_width=900, plot_height=600,
                          title='Magnitude Distribution Across Normal vs Malicious Events (Zoomed in w/Example Threshold)',
                          x_axis_label='Magnitude',
                          y_axis_label='Observations',
                          y_range=(0, mal_count * .33),
                          x_range=(norm_mean + (norm_stddev * 2.5), mal_mean + (mal_stddev * 3)),
                          )

    overlap_view.quad(bottom=0, top=mal_hist_df.magnitude, left=mal_hist_df.left, right=mal_hist_df.right,
                      legend_label='malicious', fill_color='purple', alpha=.85)
    overlap_view.quad(bottom=0, top=norm_hist_df.magnitude, left=norm_hist_df.left, right=norm_hist_df.right,
                      legend_label='normal', fill_color='cyan', alpha=.35)

    # 3 sigma reference line
    thresh = Span(location=norm_mean + (norm_stddev * 3), dimension='height', line_color='grey',
                  line_dash='dashed', line_width=2)
    thresh_label = Label(x=norm_mean + (norm_stddev * 3), y=mal_count * .33 * .95,
                         text='3 Std Dev Threshold')
    overlap_view.add_layout(thresh)
    overlap_view.add_layout(thresh_label)

    overlap_view.legend.location = "top_right"
    show(overlap_view)

    # Density version
    malicious_hist_dense, malicious_edge_dense = np.histogram(malicious, density=True, bins=100)
    mal_hist_dense_df = pd.DataFrame({
        'magnitude': malicious_hist_dense,
        'left': malicious_edge_dense[:-1],
        'right': malicious_edge_dense[1:]
    })

    normal_hist_dense, normal_edge_dense = np.histogram(normal, density=True, bins=100)
    norm_hist_dense_df = pd.DataFrame({
        'magnitude': normal_hist_dense,
        'left': normal_edge_dense[:-1],
        'right': normal_edge_dense[1:]
    })

    density = figure(plot_width=900, plot_height=600,
                     title='Probability Density Across Normal vs Malicious Events',
                     x_axis_label='Magnitude',
                     y_axis_label='% of Group Total'
                     )

    density.quad(bottom=0, top=mal_hist_dense_df.magnitude, left=mal_hist_dense_df.left,
                 right=mal_hist_dense_df.right, legend_label='malicious', fill_color='purple', alpha=.85)
    density.quad(bottom=0, top=norm_hist_dense_df.magnitude, left=norm_hist_dense_df.left,
                 right=norm_hist_dense_df.right, legend_label='normal', fill_color='cyan', alpha=.35)

    density.legend.location = "top_right"
    show(density)


if __name__ == "__main__":
    main()
    time.sleep(1)
    print('\nGood luck catching the bad guys!')

