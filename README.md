SSL Scan
========

This is a lightweight ssl scanner based on https://github.com/rbsec/sslscan. 

It is highly recommended that you perform this on a cloud VM, not on your
home network or farmshare.

Dependencies
============

    sudo apt-get install libssl-dev golang sqlite3 mercurial
    export GOPATH=$HOME/go



This has been confirmed to work with OpenSSL 1.0.2d and go 1.5.1 on Ubuntu 15.10. 
Testing performed with OpenSSL 1.0.2g and go 1.7.4 on Ubuntu 17.04. 
Known issues with go 1.2
Requires OpenSSL >= 1.0.2 for SSL_get_server_tmp_key.

Scripts
====

    scripts/runall.sh

Will run the entire dataset, and should take ~12 days.

    scripts/runRand.sh

Will run 25,000 randomly selected from the top 1 million, should take ~ 8 hours.
The script may hang on a few outstanding hosts. If so, you can kill the scanner
and manually trigger the populator and analyzer:

    $GOPATH/bin/sslScanGo -populate && $GOPATH/bin/sslScanGo -analyze

Which should finish in a few minutes.

To just analyze our pre-scanned data without running your own scan, run

    scripts/analyzePreScanned.sh

will extract the archived scan outputs from archive.tar, and run the populator
and analyzer. This will take approximately 30 minutes. The extraction will
take a few minuts and show no progress, but the populator will report
every 10,000 rows filled.
WARNING: You should not run this script in a directory
or one monitored by a cloud service such as Dropbox or iCloud Drive, it
will create a directory with a million files (total size ~20MB).
  
Specific Usage
=====
Run

    go get github.com/mmx1/sslScanGo

to fetch the source and its dependencies, then build with 

    go install github.com/mmx1/sslScanGo


And run:

    $GOPATH/bin/sslScanGo

Run the database conversion with: 
    $GOPATH/bin/sslScanGo -populate

This will read from ./data/ and output ./scanDb.sqlite in the folder where
the original go code is located. data/ directory should be a full of only 
json files that are from the output of sslScanGo

Note: Go language requires a specific setup of where the code is and where
the executable is. This is why the GOPATH system variable is so important.
 

To run the queries on the database:

    $GOPATH/bin/sslScanGo -analyze

executes the query code and outputs  files:
  1) BigResult.txt => main result of the paper comparing hosts that utilize
      DHE key exchange for the TLS handshake with the number of hosts that
      utilize weak DHE parameters (i.e. keyexchange bits < authentication
      key bits)
  2) mainResult.png => plot of key exchange key strength vs authentication key strength
  3) TableI.txt => List of errors from querying the domains
  4) TableII.txt => What the hosts utilize for key exchange (RSA, DHE, ECDHE)
  5) TableIII.txt => Number of hosts for each key size of DHE
  6) TableIV.txt => Enumerating the curves used for EC key exchange suites
  7) TableV.txt => Enumerating authentication algorithms
  8) TableVI.txt => Enumerating authentication key strengths


