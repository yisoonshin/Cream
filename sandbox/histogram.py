# -*- coding: utf-8 -*-
#import libraries & tools for histogram
import numpy as np
import scipy.special
from bokeh.plotting import figure, output_file, show, save, ColumnDataSource
from bokeh.layouts import gridplot
from bokeh.models.tools import HoverTool
#import pandas libary to create df object from csv file
import pandas

# Read in csv
#df = pandas.read_csv('simulation_scores.csv')
df = pandas.read_csv('simulated_ddos_data.csv')
magnitude = df['magnitude']
normal_magnitude = df.loc[df.is_ddos==0,'magnitude']
malicious_magnitude = df.loc[df.is_ddos==1, 'magnitude']


def make_plot(title, hist1, hist2):
    p = figure(title=title, tools="pan,box_select,zoom_in,zoom_out,save,reset", background_fill_color="#fafafa")
    p.quad(top=hist1, bottom=0, left=edges[:-1], right=edges[1:],
           fill_color="orange", line_color="white", alpha=0.8)
    p.quad(top=hist2, bottom=0, left=edges[:-1], right=edges[1:],
          fill_color="blue", line_color="white", alpha=0.8)
    #p.line(x, pdf, line_color="#ff8888", line_width=4, alpha=0.7, legend_label="PDF")
    #p.line(x, cdf, line_color="orange", line_width=2, alpha=0.7, legend_label="CDF")

    p.y_range.start = 0
    p.y_range.end = 100
    p.x_range.start = 15000
    p.x_range.end = 30000
    p.legend.location = "center_right"
    p.legend.background_fill_color = "#fefefe"
    p.xaxis.axis_label = 'Magnitude'
    p.yaxis.axis_label = 'Frequency'
    p.grid.grid_line_color="white"
    return p




# Normal Distribution

hist1, edges = np.histogram(normal_magnitude, density=False, bins=100)
hist2, edges = np.histogram(malicious_magnitude, density=False, bins=100)

p1 = make_plot("Hypothetical Normal vs Malicious Activity Distribution", hist1, hist2)



output_file('histogram.html', title="histogram.py example")

show(gridplot([p1], ncols=2, plot_width=500, plot_height=400, toolbar_location='right'))














# multiplier = df['multiplier']
# false_positives = df['false_positives']
# false_negatives = df['false_negatives']

# # Create ColumnDataSource from data frame
# #source = ColumnDataSource(df)

# output_file('index.html')

# # Car list
# #car_list = source.data['Car'].tolist()

# # Add plot
# p = figure(
    
#     plot_width=800,
#     plot_height=600,
#     y_range=(0,400),
#     title='FP vs FN Across Multipliers',
#     x_axis_label='Multiplier',
#     y_axis_label='Count',
#     tools="pan,box_select,zoom_in,zoom_out,save,reset"
# )

# # Render glyph
# p.line(multiplier, false_negatives, legend='false negatives', line_width=2, color='#FFA500')
# p.line(multiplier, false_positives, legend='false positives', line_width=2)

# #show in browser
# show(p)
