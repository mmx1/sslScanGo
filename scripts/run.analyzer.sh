#!/bin/bash
go get -u github.com/mmx1/sslScanGo
#read -p 'Enter File name ' filename
#read -p 'Starting Index ' startInd
#read -p 'Ending Index ' endInd

$GOPATH/bin/sslScanGo -populate
$GOPATH/bin/sslScanGo -analyze
