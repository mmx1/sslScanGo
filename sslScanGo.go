// +build cgo

package main

/*
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
*/
import "C"

import (

    "log"
    // "fmt"
    "time"
    // "crypto/tls"
    "github.com/spacemonkeygo/openssl"
    // "github.com/davecgh/go-spew/spew"
)

const rsaCiphers = "AES128-SHA256:AES256-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384"

var dhCiphers = []string{"DH-RSA-AES128-SHA256", 
                           "DH-RSA-AES256-SHA256",
                           "DH-RSA-AES128-GCM-SHA256",
                           "DH-RSA-AES256-GCM-SHA384",

                           "DHE-RSA-AES128-SHA256",
                           "DHE-RSA-AES256-SHA256",
                           "DHE-RSA-AES128-GCM-SHA256",
                           "DHE-RSA-AES256-GCM-SHA384",

                           "DHE-DSS-AES128-SHA256",
                           "DHE-DSS-AES256-SHA256",
                           "DHE-DSS-AES128-GCM-SHA256",
                           "DHE-DSS-AES256-GCM-SHA384",

                           "ECDHE-RSA-AES128-SHA256",
                           "ECDHE-RSA-AES256-SHA384",
                           "ECDHE-RSA-AES128-GCM-SHA256",
                           "ECDHE-RSA-AES256-GCM-SHA384",

                           "ECDHE-ECDSA-AES128-SHA256",
                           "ECDHE-ECDSA-AES256-SHA384",
                           "ECDHE-ECDSA-AES128-GCM-SHA256",
                           "ECDHE-ECDSA-AES256-GCM-SHA384",

                           "ADH-AES128-SHA256",
                           "ADH-AES256-SHA256",
                           "ADH-AES128-GCM-SHA256",
                           "ADH-AES256-GCM-SHA384"}

type sslCheckOptions struct {
  host string
  port int
}

func testConnection() {

}


func (s sslCheckOptions) testProtocolCipher (cipherName string) {
  const request = "GET / HTTP/1.0\r\nUser-Agent: SSLScan\r\nHost: %s\r\n\r\n"

  //creates TLS context (SSL disabled by default)
  context, err := openssl.NewCtxWithVersion(0x06)
  if err != nil {
          log.Fatal(err)
  }

  err = context.SetCipherList ( cipherName )
  if err != nil {
    log.Fatal(err)
  }

  conn, err := openssl.Dial("tcp", s.host, context, 0)
  if err != nil {
    log.Print(err)
    return
    //fmt.Sprintf("%s rejected cipher %s", s.host, cipherName)
  }
  defer conn.Close()

  // C.SSL_connect(context)

  sslCipherName, err := conn.CurrentCipher()
  if err != nil {
    log.Fatal(err)
  }
  //fmt.Sprintf("%s accepted cipher %s", s.host, sslCipherName)
  println(sslCipherName)
  conn.PrintServerTmpKey()


}

func (s sslCheckOptions) testProtocolCiphers (limiter  <-chan time.Time) {
  <-limiter
  s.testProtocolCipher(rsaCiphers)

  for _, cipher := range dhCiphers {
     <-limiter
     // fmt.Println("Tick at", time.Now())
     go s.testProtocolCipher(cipher)
  }

}

func testHost() {
  // ctx, err := NewCtx()
  // if err != nil {
  //   log.Fatal(err)
  // }

  // conn, err := openssl.Dial("tcp", "www.google.com", ctx, 0)

}

func main() {
  hostname := "dh1024.badssl.com:443"
  options := sslCheckOptions{ hostname, 443}

  limiter := time.Tick(time.Millisecond * 500)
  options.testProtocolCiphers(limiter)

}