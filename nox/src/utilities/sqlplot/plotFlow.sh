#!/bin/sh
sqlite3 $1 <<EOF
.mode tabs
.output totalflow.dat
select TimeSec,TotalFlow from FlowCount where TimeSec>((select MAX(TimeSec) from FlowCount)-86400);
EOF
gnuplot plotTotalFlow.gnuplot
