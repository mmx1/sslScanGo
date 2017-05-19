package main 

import (
  "flag"
  "fmt"
)

func main() {

  startPtr := flag.Int("start", 1, "start index")
  endPtr := flag.Int("end", 0, "end index")

  flag.Parse()
  tail := flag.Args()

  if len(tail) < 1 {
    fmt.Println("Error, requires an filename argument")
    return
  }

  println("start:", *startPtr)
  println("end:", *endPtr)

}