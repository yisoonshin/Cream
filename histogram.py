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


def make_plot(title, hist, x):
    p = figure(title=title, tools="pan,box_select,zoom_in,zoom_out,save,reset", background_fill_color="#fafafa")
    p.quad(top=hist, bottom=0, left=edges[:-1], right=edges[1:],
           fill_color="orange", line_color="white", alpha=0.8)
    #p.line(x, pdf, line_color="#ff8888", line_width=4, alpha=0.7, legend_label="PDF")
    #p.line(x, cdf, line_color="orange", line_width=2, alpha=0.7, legend_label="CDF")

    p.y_range.start = 0
    p.legend.location = "center_right"
    p.legend.background_fill_color = "#fefefe"
    p.xaxis.axis_label = 'Magnitude'
    p.yaxis.axis_label = 'Frequency'
    p.grid.grid_line_color="white"
    return p




# Normal Distribution

mu, sigma = 0, 0.5

measured = np.random.normal(mu, sigma, 1000)

hist, edges = np.histogram(magnitude, density=True, bins=100)

x = np.linspace(-2, 2, 1000)
#pdf = 1/(sigma * np.sqrt(2*np.pi)) * np.exp(-(x-mu)**2 / (2*sigma**2))
#cdf = (1+scipy.special.erf((x-mu)/np.sqrt(2*sigma**2)))/2

p1 = make_plot("Hypothetical Normal vs Malicious Activity Distribution", hist, x)



output_file('histogram.html', title="histogram.py example")

show(gridplot([p1], ncols=2, plot_width=400, plot_height=400, toolbar_location='right'))














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
