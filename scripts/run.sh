#!/bin/bash
rm -f $GOPATH/bin/sslScanGo
rm -rf data
go get github.com/mmx1/sslScanGo && go install github.com/mmx1/sslScanGo
#read -p 'Enter File name ' filename
#read -p 'Starting Index ' startInd
#read -p 'Ending Index ' endInd
if [ $1 ] && [ ! $3 ]; then
	echo "Bad Format: Format is either: "
	echo "	 ./run.sh for default"
	echo "	 ./run.sh filename starting_Index ending_Index"
	exit
fi
if [ $1 ]; then
	filename=$1
else
	filename=top-1m.csv
	startInd=1
	endInd=4
fi
if [ $2 ]; then
	startInd=$2
fi
if [ $3 ]; then
	endInd=$3
fi

$GOPATH/bin/sslScanGo -r 300 -start $startInd -end $endInd $filename 