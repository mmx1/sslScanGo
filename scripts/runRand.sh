#!/bin/bash

handle_error() {
	echo "FAILED: line $1, exit code $2"
   exit 1
}

trap 'handle_error $LINENO $?' ERR

mkdir go
export GOPATH=$PWD/go

scanner="github.com/mmx1/sslScanGo"
currDir=$PWD

rm -f $GOPATH/bin/sslScanGo
go get $scanner && go install $scanner

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
	endInd=3
fi
if [ $2 ]; then
	startInd=$2
fi
if [ $3 ]; then
	endInd=$3
fi
cp top-1m.csv $GOPATH/src/$scanner
cd $GOPATH/src/$scanner
$GOPATH/bin/sslScanGo -r 300 -start $startInd -end $endInd $filename

rm -f scanDb.sqlite

$GOPATH/bin/sslScanGo -populate
$GOPATH/bin/sslScanGo -analyze


cp BigResult.txt $currDir
cp TableI.txt $currDir
cp TableII.txt $currDir
cp TableIII.txt $currDir

cd $currDir
