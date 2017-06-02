#!/bin/bash
rm -f $GOPATH/bin/sslScanGo
go get github.com/mmx1/sslScanGo && go install github.com/mmx1/sslScanGo
#read -p 'Enter File name ' filename
#read -p 'Starting Index ' startInd
#read -p 'Ending Index ' endInd

$GOPATH/bin/sslScanGo -populate
$GOPATH/bin/sslScanGo -analyze
