package main 

import (
  "bufio"
  "flag"
  "fmt"
  "os"
  "math/rand"
  "strconv"
  "time"
  "github.com/mmx1/opensslgo"
)

func main() {

  populateFlag := flag.Bool("populate", false, "Populate SQLite table from json files")
  analyzeFlag := flag.Bool("analyze", false, "Print report from SQlite")

  startPtr := flag.Int("start", 1, "start index")
  endPtr := flag.Int("end", 0, "end index")
  randSelection := flag.Int("r", -1, "num Items to be randomly selected")
  rerun := flag.String("rerun", "", "file of indices to rerun")
  tlsVersionFlag := flag.String("tls", "all", "tls versions to run")

  flag.Parse()
  tail := flag.Args()

  var sourceFile string
  if len(tail) > 0 {
    sourceFile = tail[0]
  }

  switch {
  case *populateFlag:
    parsePopulateArgs(tail)
  case *analyzeFlag:
    fmt.Println("Non-implemented analyze")
  default:
    parseScanOptions(sourceFile, 
                   *startPtr, 
                   *endPtr, 
                   *tlsVersionFlag, 
                   *rerun, 
                   *randSelection)
  }
}

func parsePopulateArgs(args []string) {
  // expect src, destination , default to data/ scanDb.sqlite
  dataDir := "./data/"
  outputName := "./scanDb.sqlite"
  switch len(args) {
    case 2:
      outputName = args[1]
      fallthrough
    case 1:
      dataDir = args[0]
  }
  populateDb(dataDir, outputName)
}
  

func parseScanOptions (sourceFile string, 
                       start int, 
                       end int, 
                       tlsVersionStr string, 
                       reRunFile string,
                       randCount int) {
  
  var selectedIndices map[int]bool
  if randCount > 0 {
    fmt.Println(randCount, "random selected, ignoring other parameters")
    selectedIndices = make(map[int]bool)
    rndGen := rand.New(rand.NewSource(time.Now().Unix()))

    for i := 0; i < randCount; i++ {
      index := int(rndGen.Float32() * 1000 + 1)
      fmt.Println("generated index", index)
      if !selectedIndices[index] {
        selectedIndices[index] = true
      }else{
        i-- //try again
      }
    }

  }else if reRunFile != "" {
    fmt.Println("Rerunning indexes from", reRunFile)
    selectedIndices = make(map[int]bool)

    f, err := os.Open(reRunFile)
    check(err)
    defer f.Close()

    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
      index, err := strconv.Atoi(scanner.Text())
      check(err)
      selectedIndices[index] = true
    }
  }
  tlsVersions := tlsFlagToSlice(tlsVersionStr)
  scan(sourceFile, start, end, selectedIndices, tlsVersions)
}

func tlsFlagToSlice(s string) ([]openssl.SSLVersion) {
  var tlsVersions []openssl.SSLVersion
  switch s {
  case "tls11":
    tlsVersions = append(tlsVersions, openssl.TLSv1_1)
  case "tls12":
    tlsVersions = append(tlsVersions, openssl.TLSv1_2)
  default:
    tlsVersions = append(tlsVersions, openssl.TLSv1_2)
    tlsVersions = append(tlsVersions, openssl.TLSv1_1)
  }
  return tlsVersions
}