# gnuplot script file for plotting the CDF for:
# Query Latency for Local Nodes at Query Interval of 100ms (i.e., excludes Japan nodes)
unset title
unset label
set autoscale
set key bottom right

set xlabel "UNIX Time (s)"
set grid x

set ylabel "Total Number of Flows"
set yr [0:]
#set ytic (0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1)
set grid y

set terminal png linewidth 3
set output "totalFlow.png"

set style line 1 lt 1 lc rgb "#CC0000" pt 0
set style line 2 lt 2 lc rgb "#00CC00" pt 0
set style line 3 lt 3 lc rgb "#0000CC" pt 0

plot "totalflow.dat" using 1:2  title 'Total Flow'with linespoints ls 1
