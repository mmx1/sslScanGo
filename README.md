SSL Scan
========

This is a lightweight ssl scanner based on https://github.com/rbsec/sslscan,
written for CS244 to reproduce the scan results of
[An Experimental Study of TLS Forward Secrecy Deployments](http://www.w2spconf.com/2014/papers/TLS.pdf)

It is highly recommended that you perform this on a cloud VM, not on your
home network or farmshare.

Create a VM Instance in Google Cloud
====================================
Ubuntu 17.04 
CPU 3.75
Hard disk 20 GB => will not work with a smaller disk

SSH into the VM and run code below. 

Dependencies
============
This requires the following libraries (and for $GOPATH to be set)

    sudo apt-get install libssl-dev golang sqlite3 mercurial
    export GOPATH=$HOME/go

This has been confirmed to work with OpenSSL 1.0.2d and go 1.5.1 on Ubuntu 15.10. 
Testing performed with OpenSSL 1.0.2g and go 1.7.4 on Ubuntu 17.04. 
Known issues with go 1.2
Requires OpenSSL >= 1.0.2 for SSL_get_server_tmp_key.

Fetch Code
===========

    go get github.com/mmx1/sslScanGo

will fetch the source and its dependencies. This will take approximately 
6 seconds to complete depending on your network connection. 

Scripts
=========
Three Main Scripts: 
1) analyzeStatic.sh
2) runRand.sh
3) runall.sh

Overview:
Each script will populate a database with the data and analyze the data
by creating output files for each main result from the paper (HABJ). After
creating the output files, the script will initiate a HTTP server on port 80.
Use the VM's external facing IP address to access the files.

Differences: 
1) analyzeStatic.sh -> will not make any queries but will utilize our archived
  data we captured to create our blog post, so you can see the same results.
  This script takes about 30 minutes.
2) runRand.sh -> collects data from a 20000 domain random sample of the 1 million websites. 
    This script is meant to show a representation of the work in a reasonable amount
    of time. This script takes 8 hours.
3) runall.sh -> collectss data from the top 1 million websites, 
  which is used to create the results in the blog post. This data is archived 
  for use with analyzeStatic.sh. This script will take 12 DAYS.

Recommend only running 1 & 2 for reproducing the results:
  
1) Run script analyzeStatic.sh to see results in blog post. (30 min)

        $GOPATH/src/github.com/mmx1/sslScanGo/scripts/analyzeStatic.sh
    
  WARNING: You should not run this script in a directory
    or one monitored by a cloud service such as Dropbox or iCloud Drive, it
    will create a directory with a million files (total size ~20MB).

2) Run runRand.sh to collect and analyze sample of the data (8 hours)

        $GOPATH/src/github.com/mmx1/sslScanGo/scripts/runRand.sh > output.txt & disown    

3) run runall.sh to collect and analyze all 1million domains (12 days)
    
        $GOPATH/src/github.com/mmx1/sslScanGo/scripts/runall.sh > output.txt & disown

* Disowning the process will allow you to safely logout, come back, and 
    inspect the tail of the progress file.

        tail -f output.txt

* The script may hang on a few outstanding hosts. If so, you can kill the scanner 
    and manually trigger the populator and analyzer:

        $GOPATH/bin/sslScanGo -populate && $GOPATH/bin/sslScanGo -analyze

    Which will finish in about 2 minutes.
    To view the results:
    
      sudo python -m SimpleHTTPServer 80

    View by going to:

      http://externalIPAddress
  
Specific Usage
=====
Run

    go get github.com/mmx1/sslScanGo

to fetch the source and its dependencies.

And run:

    $GOPATH/bin/sslScanGo

The default for sslScanGo is to run the scanner on the entire top-1m.csv 
file.

Run the database conversion with: 

    $GOPATH/bin/sslScanGo -populate

This will read from ./data/ and output ./scanDb.sqlite in the folder where
the original go code is located. data/ directory should be a full of only 
json files that are from the output of sslScanGo

Note: Go language requires a specific setup of where the code is and where
the executable is. This is why the GOPATH system variable is so important.
 

To run the queries on the database:

    $GOPATH/bin/sslScanGo -analyze

executes the query code and outputs files below. 

Output Files 
============
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
