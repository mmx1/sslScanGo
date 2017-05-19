SSL Scan
========

This is a lightweight ssl scanner based on https://github.com/rbsec/sslscan. 

Setup
=====
Setup your `$GOPATH`, then run

    go get github.com/mmx1/sslScanGo

Build with 

    go install github.com/mmx1/sslScanGo


And run:

    $GOPATH/bin/sslScanGo

Dependencies
============
This has been confirmed to work with OpenSSL 1.0.2d and go 1.5.1 on Ubuntu 15.10. Known issues with go 1.2 and requires OpenSSL > 1.0.2 for SSL_get_server_tmp_key.

