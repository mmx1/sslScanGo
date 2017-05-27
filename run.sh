#!/bin/bash
rm -f $GOPATH/bin/sslScanAnalyzer
go get github.com/mmx1/sslScanAnalyzer && go install github.com/mmx1/sslScanAnalyzer
#read -p 'Enter File name ' filename
#read -p 'Starting Index ' startInd
#read -p 'Ending Index ' endInd

$GOPATH/bin/sslScanAnalyzer