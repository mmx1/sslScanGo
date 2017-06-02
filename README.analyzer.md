Required Dependencies: 
sudo apt-get install openssl, libssl-dev, golang, sqlite3
export GOPATH=$HOME/go

To build the Analyzer: 
go get github.com/mmx1/sslScanAnalyzer 
go install github.com/mmx1/sslScanAnalyzer

These commands will build the executable in and all required dependencies: 
$GOPATH/bin/

Run Analyzer with: 
$GOPATH/bin/sslScanAnalyzer

This will read from ./data/ and output ./scanDb.sqlite in the folder where
the original go code is located. data/ directory should be a full of only 
json files that are from the output of sslScanGo

Note: Go language requires a specific setup of where the code is and where
the executable is. This is why the GOPATH system variable is so important.

The database query executable is not compiled with the go install ... command
and must be compiled separately which allows for changing the queries while
the underlying database does not change. This allows for incremental testing 
on an existing database. 

To run the queries on the database:
go build dbHelper/queryDB.go => outputs queryDB executable in working
		directory. 
./queryDB => executes the query code and outputs 3 files:
	1) BigResult.txt => main result of the paper comparing hosts that utilize
			DHE key exchange for the TLS handshake with the number of hosts that
			utilize weak DHE parameters (i.e. keyexchange bits < authentication
			key bits)
	2) TableI.txt => List of errors from querying the domains
	3) TableII.txt => What the hosts utilize for key exchange (RSA, DHE, ECDHE)
	4) TableIII.txt => Number of hosts for each key size of DHE


