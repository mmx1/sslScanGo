#!/bin/bash

handle_error() {
	echo "FAILED: line $1, exit code $2"
   exit 1
}

trap 'handle_error $LINENO $?' ERR

export GOPATH=$HOME/go

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
	filename=short.csv
	startInd=1
	endInd=3
fi
if [ $2 ]; then
	startInd=$2
fi
if [ $3 ]; then
	endInd=$3
fi

cd $GOPATH/src/$scanner
$GOPATH/bin/sslScanGo -start $startInd -end $endInd $filename

analyzer="github.com/mmx1/sslScanAnalyzer"
go get $analyzer && go install $analyzer

rm -rf $GOPATH/src/$analyzer/data
mv data $GOPATH/src/$analyzer
cd $GOPATH/src/$analyzer

rm -f scanDb.sqlite

$GOPATH/bin/sslScanAnalyzer
go build dbHelper/queryDB.go
./queryDB

cp BigResult.txt $currDir
cp TableI.txt $currDir
cp TableII.txt $currDir
cp TableIII.txt $currDir

cd $currDir