#!/bin/bash

echo "FAILED: line $1, exit code $2"
   exit 1
}
trap 'handle_error $LINENO $?' ERR

export GOPATH=$HOME/go

scanner="github.com/mmx1/sslScanGo"
currDir=$PWD

rm -rf $GOPATH/src/github.com/mmx1/sslScanGo/
go get $scanner && go install $scanner