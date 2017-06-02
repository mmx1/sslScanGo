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

    sudo apt-get install libssl-dev, golang, sqlite3, hg
    export GOPATH=$HOME/go

This has been confirmed to work with OpenSSL 1.0.2d and go 1.5.1 on Ubuntu 15.10. 
Testing performed with OpenSSL 1.0.2g and go 1.7.4 on Ubuntu 17.04. 
Known issues with go 1.2
Requires OpenSSL >= 1.0.2 for SSL_get_server_tmp_key.


Run the database conversion with: 
    $GOPATH/bin/sslScanGo -populate

This will read from ./data/ and output ./scanDb.sqlite in the folder where
the original go code is located. data/ directory should be a full of only 
json files that are from the output of sslScanGo

Note: Go language requires a specific setup of where the code is and where
the executable is. This is why the GOPATH system variable is so important.
 

To run the queries on the database:

    $GOPATH/bin/sslScanGo -analyze

executes the query code and outputs 3 files:
  1) BigResult.txt => main result of the paper comparing hosts that utilize
      DHE key exchange for the TLS handshake with the number of hosts that
      utilize weak DHE parameters (i.e. keyexchange bits < authentication
      key bits)
  2) TableI.txt => List of errors from querying the domains
  3) TableII.txt => What the hosts utilize for key exchange (RSA, DHE, ECDHE)
  4) TableIII.txt => Number of hosts for each key size of DHE


