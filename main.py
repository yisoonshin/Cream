from bokeh.plotting import figure, output_file, show, save, ColumnDataSource
from bokeh.models.tools import HoverTool
from bokeh.transform import factor_cmap
from bokeh.palettes import Blues8
from bokeh.embed import components
#import libraries for histogram charts
from bokeh.layouts import gridplot
import numpy as numpy
import scripy.special
#import pandas libary to parse through csv file
import pandas

# Read in csv
df = pandas.read_csv('simulation_scores.csv')

multiplier = df['multiplier']
false_positives = df['false_positives']
false_negatives = df['false_negatives']

# Create ColumnDataSource from data frame
#source = ColumnDataSource(df)

output_file('index.html')

# Car list
#car_list = source.data['Car'].tolist()

# Add plot
p = figure(
    
    plot_width=800,
    plot_height=600,
    y_range=(0,400),
    title='FP vs FN Across Multipliers',
    x_axis_label='Multiplier',
    y_axis_label='Count',
    tools="pan,box_select,zoom_in,zoom_out,save,reset"
)

# Render glyph
p.line(multiplier, false_negatives, legend='false negatives', line_width=2, color='#FFA500')
p.line(multiplier, false_positives, legend='false positives', line_width=2)

#show in browser
show(p)
