#!/bin/bash

echo "FAILED: line $1, exit code $2"
   exit 1
}
trap 'handle_error $LINENO $?' ERR

export GOPATH=$HOME/go

scanner="github.com/mmx1/sslScanGo"

go get -u $scanner

rm -rf data
rm -f scanDb.sqlite

cp $GOPATH/src/$scanner/resources/archive.tar.gz .
tar -xzf archive.tar.gz

$GOPATH/bin/sslScanGo -populate
$GOPATH/bin/sslScanGo -analyze

sudo python -m simpleHTTPServer 80