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

  "image/color"

  "github.com/gonum/plot"
  "github.com/gonum/plot/plotter"
  "github.com/gonum/plot/vg"
)

func analyze(dbName string) {
  db, err := sql.Open("sqlite3", dbName)
  check(err)
  defer db.Close()

  numTLSHosts := printTableI(db)
  printTableII_V(db, numTLSHosts)
  numDHEEnabled := printMainResult(db)
  printMainGraph(db)
  printTableIII(db, numDHEEnabled)
  printTableIV(db)
  printTableVI(db)
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
  defer tableIFile.Close()

  _, err = tableIFile.WriteString("Connection errors during TLS survey\n")
  printTableFileHeader(tableIFile, 26, []string{"Error", "Hosts"})
  printTableToFile(tableIFile, 26, []string{"Connection Refused Error", strconv.Itoa(connRefusedCnt) } )
  printTableToFile(tableIFile, 26, []string{"SSL Errors", strconv.Itoa(sslErrCnt - numTLSHosts) })
  printTableToFile(tableIFile, 26, []string{"Timeout", strconv.Itoa(timeoutCnt)})
  printTableToFile(tableIFile, 26, []string{"Invalid Host Name", strconv.Itoa(invalidHostnameCnt)})

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

  _, err = tableIIFile.WriteString("Key exchange method support on TLS servers\n")
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

  _, err = tableVFile.WriteString("Authentication method support on TLS servers\n")
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
  defer tableIIIFile.Close()

  _, err = tableIIIFile.WriteString("Diffie-Hellman parameter size support for DHE key exchange\n")
  printTableFileHeader(tableIIIFile, 14, []string{"Size(bits)", "Hosts", "HABJ'14"})
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
  //No DHE and EC pairing
  //select count(*) from handshakes where keyexid = 28 AND authid != 6;

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
  _, err = brFile.WriteString("Hosts using weaker DH Parameters than Authentication Key strength\n")
  printTableFileHeader(brFile, 20, []string{"", "2017",  "HABJ'14"})
  printTableToFile(brFile, 20, []string{"Weak DH Parameters", badPercentage, "82.9%"} )
  printTableToFile(brFile, 20, []string{"Total DHE hosts", strconv.Itoa(numDHEEnabled), "283,647"} )

  brFile.Close()

  return numDHEEnabled
}

func printMainGraph (db *sql.DB) {
  dropTable("graph_output", db)
  createTmpTableQuery := `create table graph_output as select * 
                          from handshakes 
                          where keyexid = 28 and authid = 6`
  _, err := db.Exec(createTmpTableQuery)
  check(err)
  defer dropTable("graph_output", db)

  keEquals := tupleQuery("keyexbits = authbits", db)
  keyexless := tupleQuery("keyexbits < authbits", db)
  keyexmore := tupleQuery("keyexbits > authbits", db)

  p, err := plot.New()
  check(err)
  p.Title.Text = "Comparison of DH parameter size to RSA key strength"
  p.X.Label.Text = "RSA key size (bits)"
  p.Y.Label.Text = "DH parameter size (bits)"

  bequals, err := plotter.NewBubbles(keEquals, vg.Points(3), vg.Points(20))
  check(err)
  bequals.Color = color.RGBA{R: 0, G:255, B: 0, A: 255}
  p.Add(bequals)

  beless, err := plotter.NewBubbles(keyexless, vg.Points(3), vg.Points(20))
  check(err)
  beless.Color = color.RGBA{R: 255, G:100, B: 0, A: 255}
  p.Add(beless)

  bemore, err := plotter.NewBubbles(keyexmore, vg.Points(3), vg.Points(20))
  check(err)
  bemore.Color = color.RGBA{R: 255, G:200, B: 0, A: 255}
  p.Add(bemore)

  err = p.Save(9*vg.Inch, 9*vg.Inch, "mainResult.png")
  check(err)

}

func dropTable(s string, db *sql.DB) {
  dropTable := "drop table if exists " + s
  _, err := db.Exec(dropTable)
  check(err)
}

type graphTuple struct{
  count int
  keyexbits int
  authbits int 
}

type graphData []graphTuple

// plotter.XYZer interface
func (tuples graphData) Len() int {
  return len(tuples)
}

func (tuples graphData) XYZ(i int) (float64, float64, float64) {
  t := tuples[i]
  return float64(t.authbits), float64(t. keyexbits), float64(t.count)
}

func tupleQuery(predicate string, db *sql.DB) graphData {
  format := `select count(host), keyexbits, authbits 
             from graph_output 
             where %s group by keyexbits, authbits `
  query := fmt.Sprintf(format, predicate)
  rows, err := db.Query(query)
  check(err)
  defer rows.Close()
  var result []graphTuple
  for rows.Next() {
    var tuple graphTuple
    err = rows.Scan(&tuple.count, &tuple.keyexbits, &tuple.authbits)
    check(err)
    result = append(result, tuple)
  }
  return result
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
  defer tableIVFile.Close()

  _, err = tableIVFile.WriteString("Elliptic curves used for ECDHE key exchange\n")
  printTableFileHeader(tableIVFile, 15, []string{"Curve", "Hosts"},)
  for name, hosts := range curveCount {
    resultStr := formatPercent(hosts, numECKE)
    transName, prevData := curveLookup(name)
    printTableToFile(tableIVFile, 15,  []string{transName, resultStr, prevData} )
  }
  _, err = tableIVFile.WriteString("\nTotal EC Key Exchange Servers: "+strconv.Itoa(numECKE))
  check(err)
}

func printTableVI (db *sql.DB) {
  numRSAAuth := singleIntQuery("select count (distinct host) from handshakes where authid = 6", db)

  buckets := make(map[string]int) 
  buckets["≤ 512"]       = singleIntQuery("select count (distinct host) from handshakes where authbits <= 512 and authid = 6", db)
  buckets["513 - 1023"]  = singleIntQuery("select count (distinct host) from handshakes where authbits > 512 and authbits < 1024 and authid = 6", db)
  buckets["1024"]        = singleIntQuery("select count (distinct host) from handshakes where authbits = 1024 and authid = 6", db)
  buckets["1025 - 2047"] = singleIntQuery("select count (distinct host) from handshakes where authbits > 1024 and authbits < 2048 and authid = 6", db)
  buckets["2048"]        = singleIntQuery("select count (distinct host) from handshakes where authbits = 2048 and authid = 6", db)
  buckets["2049 - 4095"] = singleIntQuery("select count (distinct host) from handshakes where authbits > 2048 and authbits < 4096 and authid = 6", db)
  buckets["4096"]        = singleIntQuery("select count (distinct host) from handshakes where authbits = 4096 and authid = 6", db)
  buckets["≥ 4097"]      = singleIntQuery("select count (distinct host) from handshakes where authbits > 4096 and authid = 6", db)

  //Create TableIV File and fill with data
  tableVIFile, err := os.Create("TableVI.txt")
  check(err)
  defer tableVIFile.Close()

  _, err = tableVIFile.WriteString("RSA key sizes of TLS server certificates\n")
  printTableFileHeader(tableVIFile, 15, []string{"Size (bits)", "Hosts", "HABJ'14", "IMC'13", "IMC'07"})
  percentStr := formatPercent(buckets["≤ 512"] , numRSAAuth)
  printTableToFile(tableVIFile, 15,  []string{"≤ 512", percentStr, "350 (0.0%)", "0.1%", "3.94%"} )

  percentStr = formatPercent(buckets["513 - 1023"] , numRSAAuth)
  printTableToFile(tableVIFile, 15,  []string{"513 - 1023", percentStr, "20 (0.0%)", "0.0%", "1.42%"} )

  percentStr = formatPercent(buckets["1024"] , numRSAAuth)
  printTableToFile(tableVIFile, 15,  []string{"1024", percentStr, "87,760 (18.5%)", "10.5%", "88.35%"} )

  percentStr = formatPercent(buckets["1025 - 2047"] , numRSAAuth)
  printTableToFile(tableVIFile, 15,  []string{"1025 - 2047", percentStr, "20 (0.0%)", "0.7%", "0.01%"} )

  percentStr = formatPercent(buckets["2048"] , numRSAAuth)
  printTableToFile(tableVIFile, 15,  []string{"2048", percentStr, "374,294 (79.0%)", "86.4%", "6.14%"} )

  percentStr = formatPercent(buckets["2049 - 4095"] , numRSAAuth)
  printTableToFile(tableVIFile, 15,  []string{"2049 - 4095", percentStr, "251 (0.0%)", "0.0%", "0.00%"} )

  percentStr = formatPercent(buckets["4096"] , numRSAAuth)
  printTableToFile(tableVIFile, 15,  []string{"4096", percentStr, "11,093 (2.3%)", "2.3%", "0.19%"} )

  percentStr = formatPercent(buckets["≥ 4097"] , numRSAAuth)
  printTableToFile(tableVIFile, 15,  []string{"≥ 4097", percentStr, "22 (0.0%)", "0.0%", "0.00%"} )
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



