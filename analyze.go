package main

import (
  "database/sql"
  "fmt"
  _ "github.com/mattn/go-sqlite3"
  "log"
  "os"
  "sort"
  "strconv"
  "strings"
)

func analyze(dbName string) {
  db, err := sql.Open("sqlite3", dbName)
  check(err)
  defer db.Close()

  numTLSHosts := printTableI(db)
  printTableII_V(db, numTLSHosts)
  numDHEEnabled := printMainResult(db)
  printTableIII(db, numDHEEnabled)
  printTableIV(db)
}

func printTableI (db *sql.DB) (int) {
    //Table I : Errors
  var numTLSHosts int
  err := db.QueryRow("select count(distinct host) from handshakes").Scan(&numTLSHosts)
  check(err)

  connRefusedCnt := queryNumError(db, 1)
  sslErrCnt := queryNumError(db, 2)
  timeoutCnt := queryNumError(db, 4)
  invalidHostnameCnt := queryNumError(db, 8)

  tableIFile, err := os.Create("TableI.txt")
  check(err)
  printTableFileHeader(tableIFile, 26, []string{"Error", "Hosts"})
  printTableToFile(tableIFile, 26, []string{"Connection Refused Error", strconv.Itoa(connRefusedCnt) } )
  printTableToFile(tableIFile, 26, []string{"SSL Errors", strconv.Itoa(sslErrCnt - numTLSHosts) })
  printTableToFile(tableIFile, 26, []string{"Timeout", strconv.Itoa(timeoutCnt)})
  printTableToFile(tableIFile, 26, []string{"Invalid Host Name", strconv.Itoa(invalidHostnameCnt)})
  tableIFile.Close()

  return numTLSHosts
}

func printTableII_V (db *sql.DB, numEntries int) {
   // TABLE II CODE
  
  //used to just get the list of Key Exchange messages (columns of a single row) 
  rows, err := db.Query("select * from hosts where id=1")
  columns, err := rows.Columns()
  check(err)
  rows.Close()

  log.Println("Columns are: ", columns)
  var count []int
  for i, v := range columns {
    if i >= 3 {
        statement := fmt.Sprintf("select count(*) from hosts where %s= 1", v)
        val := singleIntQuery(statement, db)
        //log.Println("Total number of "+v+" :", val)
        count = append(count, val)
    }
  }
  log.Println(count)

  tableIIFile, err := os.Create("TableII.txt")
  check(err)
  defer tableIIFile.Close()
  
  rsaCountStr := formatPercent(count[0], numEntries)
  dheCountStr := formatPercent(count[1], numEntries)
  ecCountStr := formatPercent(count[2], numEntries)

  printTableFileHeader(tableIIFile, 14, []string{"Method", "Hosts", "HABJ'14", "IMC'07"})

  printTableToFile(tableIIFile, 14, []string{"RSA", rsaCountStr,"473,688 (99.9%)", "99.86%" } )
  printTableToFile(tableIIFile, 14, []string{"DHE", dheCountStr,"283,647 (59.8%)", "57.57%" } )
  printTableToFile(tableIIFile, 14, []string{"ECDHE", ecCountStr,"85,070 (17.9%)" } )


  tableVFile, err := os.Create("TableV.txt")
  check(err)
  defer tableVFile.Close()
  
  rsaAuthCountStr := formatPercent(count[3], numEntries)
  anonCountStr := formatPercent(count[4], numEntries)
  dsaCountStr := formatPercent(count[5], numEntries)
  ecAuthCountStr := formatPercent(count[6], numEntries)

  printTableFileHeader(tableVFile, 14, []string{"Method", "Hosts", "HABJ'14", "IMC'07"})

  printTableToFile(tableVFile, 14, []string{"RSA", rsaAuthCountStr,"473,780 (99.9%)", "≥99.86%" } )
  printTableToFile(tableVFile, 14, []string{"Anonymous", anonCountStr,"7750 (0.0%)", "0.02%" } )
  printTableToFile(tableVFile, 14, []string{"DSA", dsaCountStr,"22 (0.0%)" } )
  printTableToFile(tableVFile, 14, []string{"ECDSA/ECDH", ecAuthCountStr,"3 (0.0%)" } )

}

func printTableIII(db *sql.DB, numDHEEnabled int) {
  //TABLE III CODE
  //Get Bit Sizes
  rows, err := db.Query("select distinct keyexbits from handshakes where keyexid = 28")
  check(err)
  var dheBitSizes []int 
  for rows.Next() {
    var dheBitSize int
    err = rows.Scan(&dheBitSize)
    check(err)
    dheBitSizes = append(dheBitSizes, dheBitSize)
  }
  rows.Close()
  sort.Ints(dheBitSizes)
  log.Println("Bit Sizes are: ", dheBitSizes)


  //count number of handshakes that use each bitsize
  m := make(map[int]int)
  for _, size := range dheBitSizes {
    statement := fmt.Sprintf("select count(distinct host) from handshakes where keyexid = 28 and keyexbits = %d", int(size))
    m[size] = singleIntQuery(statement, db)
  }

  // Number of domains that allowed <1024 bits for DHE key exchange  
  lowDHE := singleIntQuery("select count(errors) from hosts where errors & 128 = 128", db)
  
  //Create TableIII File and fill with data
  tableIIIFile, err := os.Create("TableIII.txt")
  check(err)
  printTableFileHeader(tableIIIFile, 14, []string{"Size(bits)", "Hosts"})
  lowDheStr := formatPercent(lowDHE, numDHEEnabled)
  printTableToFile(tableIIIFile, 14, []string{"≤768",lowDheStr, "97,494 (34.3%)" })

  for _, bitSz := range dheBitSizes{
    currDataStr := formatPercent(m[bitSz], numDHEEnabled)
    printTableToFile(tableIIIFile, 14, []string{strconv.Itoa(bitSz), currDataStr, prevDHSizeData(bitSz)} )
  }
  _, err = tableIIIFile.WriteString("\nTotal DHE Enabled Servers: " + strconv.Itoa(numDHEEnabled))
  tableIIIFile.Close()
}

func prevDHSizeData (size int) (string) {
  switch size {
  case 1024:
    return "281,714 (99.3%)"
  case 1544:
    return "1 (0.0%)"
  case 2048:
    return "859 (0.3%)"
  case 3248:
    return "2 (0.0%)"
  case 4096:
    return "14 (0.0%)"
  default:
    return "0"
  }
}

func printMainResult (db *sql.DB) (int) {

  numDHEQuery := "select count(distinct host) from handshakes where keyexid = 28"
  numDHEEnabled := singleIntQuery(numDHEQuery, db)
  log.Println("Total DHE enabled: ", numDHEEnabled)

  badDHEParamQuery := `select count(distinct host) 
                       from handshakes 
                       where keyexid = 28 AND authid = 6 AND keyexbits < authbits`
  numBadDHEParam := singleIntQuery(badDHEParamQuery, db)
  log.Println("Total number of bad DHE params: ", numBadDHEParam)

  //New Version of openssl does not accept connections with key size lower than 1024
  //Captured as error flag 1 << 7 or 128
  //Find all DHE requests that did not progress to a Handshake
  lowDHEQuery := "select count(errors) from hosts where errors & 128 = 128 and errors & 256 = 0"
  lowDHEUnreported := singleIntQuery(lowDHEQuery, db)
  //Include non-reported handshakes
  numBadDHEParam += lowDHEUnreported
  numDHEEnabled += lowDHEUnreported

  brFile, err := os.Create("BigResult.txt")
  check(err)

  badPercentage :=  formatPercent(numBadDHEParam, numDHEEnabled) 
  printTableFileHeader(brFile, 15, []string{"", "2017",  "HABJ'14"})
  printTableToFile(brFile, 15, []string{"Weak DH Parameters", badPercentage, "82.9%"} )
  printTableToFile(brFile, 15, []string{"Total DHE hosts", strconv.Itoa(numDHEEnabled), "283,647"} )

  brFile.Close()

  return numDHEEnabled
}

func printTableIV (db *sql.DB) {

  numECKEQuery := "select count(distinct host) from handshakes where keyexid = 408"
  numECKE := singleIntQuery(numECKEQuery, db)

  curveRows, err := db.Query("select distinct keyexcurve from handshakes")
  check(err)
  var keCurves []string 
  for curveRows.Next() {
    var curveName string
    err = curveRows.Scan(&curveName)
    check(err)
    if curveName != "" {
      keCurves = append(keCurves, curveName)
    }
  }
  curveRows.Close()

  curveCount := make(map[string]int)
  for _, name := range keCurves {
    curveCountQuery := fmt.Sprintf("select count (distinct host) from handshakes where keyexcurve is '%s'", name)
    curveCount[name] = singleIntQuery(curveCountQuery, db)
  }

  //Create TableIV File and fill with data
  tableIVFile, err := os.Create("TableIV.txt")
  check(err)
  printTableFileHeader(tableIVFile, 15, []string{"Curve", "Hosts"},)

  for name, hosts := range curveCount {
    resultStr := formatPercent(hosts, numECKE)
    transName, prevData := curveLookup(name)
    printTableToFile(tableIVFile, 15,  []string{transName, resultStr, prevData} )
  }
  _, err = tableIVFile.WriteString("\nTotal EC Key Exchange Servers: "+strconv.Itoa(numECKE))
  tableIVFile.Close()
}

func printTableVI () {

}

func curveLookup (s string) (string, string) {
  switch s{
  case "P-256":
    return "secp256r1", "81,789 (96.1%)"
  case "P-384":
    return "secp384r1", "86 (0.1%)"
  case "P-521":
    return "secp521r1", "73 (0.0%)"
  case "B-571":
    return "sect571r1", "316 (0.3%)"
  case "brainpoolP512r1":
    return "brainpoolP512r1", "0"
  case "secp256k1":
    return "secp256k1", "0"
  default:
    return "", ""
  }
}

func printTableFileHeader(f *os.File, width int, labels []string) {
  printTableToFile(f, width, labels)
  _, err := f.WriteString(strings.Repeat("-", width * len(labels)) + "\n")
  check(err)  
}

func printTableToFile(f *os.File, width int, labels []string) {
  cellFormat := fmt.Sprintf("%%-%ds\t", width)
  var line string
  for _, label := range labels {
    line += fmt.Sprintf(cellFormat, label)
  }
  line += "\n"

  _, err := f.WriteString(line)
  check(err)
}

func formatPercent(n int, total int) (string) {
  per := float64(n)/float64(total)  * 100
  return fmt.Sprintf("%d (%s%%)", n, strconv.FormatFloat(per, 'f', 2, 64))
}

func singleIntQuery(q string, db *sql.DB) (int) {
  var result int
  err := db.QueryRow(q).Scan(&result)
  check(err)
  return result
}

func queryNumError (db *sql.DB, bit int) int {
  statement := fmt.Sprintf("select count(id) from hosts where errors & %d = %d", bit, bit)
  return singleIntQuery(statement, db)
}



