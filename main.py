from bokeh.plotting import figure, output_file, show, save, ColumnDataSource
from bokeh.models.tools import HoverTool
from bokeh.transform import factor_cmap
from bokeh.layouts import row
#from bokeh.palettes import Blues8
from bokeh.embed import components
import pandas
#from bokeh.charts import Histogram
from bokeh.sampledata.autompg import autompg as df
from bokeh.io import show, output_file

# Read in csv
df = pandas.read_csv('simulation_scores.csv')

multiplier = df['multiplier']
false_positives = df['false_positives']
false_negatives = df['false_negatives']
threshold = df['threshold']
precision = df['precision']
recall = df['recall']
f1_score = df['f1_score']

output_file('index.html')


# 1st plot FP Vs FN across Multipliers 
p = figure(
    
    plot_width=500,
    plot_height=300,
    y_range=(0,400),

    title='FP vs FN Across Multipliers',
    x_axis_label='Multiplier',
    y_axis_label='Count',
    tools="pan,box_select,zoom_in,zoom_out,save,reset"
)
#2nd plot FP vs FN across Threshold Levels
p2 = figure(


    plot_width=500,
    plot_height=300,
    y_range=(0,400),
    x_range=(14000,30000),

    title='FP vs FN across Threshold Levels',
    x_axis_label='Threshold',
    y_axis_label='Count',
    tools="pan,box_select,zoom_in,zoom_out,save,reset"

)
# 3rd plot Evaluation Metrics Across Multiplier Levels
p3 = figure(


    plot_width=500,
    plot_height=300,
    y_range=(0,1.0),
    x_range=(3,8),

    title='Evaluation Metrics Across Multiplier Levels',
    x_axis_label='Multiplier',
    y_axis_label='Score',
    tools="pan,box_select,zoom_in,zoom_out,save,reset"

)
# Render glyph
p.line(multiplier, false_negatives, legend_label='FN', line_width=2, color="#FFD700" )
p.line(multiplier,false_positives, legend_label='FP',line_width=2)
p2.line(threshold, false_negatives, legend_label='FN', line_width=2, color="#FFD700" )
p2.line(threshold,false_positives, legend_label='FP',line_width=2)
p3.line(multiplier,precision,legend_label='precision',line_width=2, color="#f5ad42")
p3.line(multiplier,recall,legend_label='recall',line_width=2, color="#f7300c")
p3.line(multiplier,f1_score,legend_label='f1_score',line_width=2, color="#cc5697")
show(row(p,p2,p3))
