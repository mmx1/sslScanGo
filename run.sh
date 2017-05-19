#!/bin/bash
rm -f $GOPATH/bin/sslScanGo
go get github.com/mmx1/sslScanGo && go install github.com/mmx1/sslScanGo
$GOPATH/bin/sslScanGo -start 1 -end 4 short.csv