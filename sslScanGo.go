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
    // "crypto/tls"
    "github.com/spacemonkeygo/openssl"
    // "github.com/davecgh/go-spew/spew"
)

type sslCheckOptions struct {
  host string
  port int
}

func testConnection() {

}


func (s sslCheckOptions) testProtocolCipher (cipherName string) {
  const request = "GET / HTTP/1.0\r\nUser-Agent: SSLScan\r\nHost: %s\r\n\r\n"

  //creates TLS context (SSL disabled by default)
  context, err := openssl.NewCtx()
  if err != nil {
          log.Fatal(err)
  }

  err = context.SetCipherList ( cipherName )
  if err != nil {
    log.Fatal(err)
  }

  conn, err := openssl.Dial("tcp", s.host, context, 0)
  if err != nil {
    log.Fatal(err)
  }
  defer conn.Close()

  // C.SSL_connect(context)

  sslCipherName, err := conn.CurrentCipher()
  if err != nil {
    log.Fatal(err)
  }
  println(sslCipherName)



}

func testHost() {
  // ctx, err := NewCtx()
  // if err != nil {
  //   log.Fatal(err)
  // }

  // conn, err := openssl.Dial("tcp", "www.google.com", ctx, 0)

}

func main() {
  options := sslCheckOptions{"www.yahoo.com:443" , 443}
  options.testProtocolCiphers("DHE-RSA-AES256-SHA256")

}