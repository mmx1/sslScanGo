// +build cgo

package main

/*
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
*/
import "C"

import (
    "log"
    "fmt"
    "strings"
    "time"
    "net" 
    "github.com/mmx1/opensslgo"
)

type sslCheckOptions struct {
  host string
  port int
  hostTicker *time.Ticker
  globalTicker *time.Ticker
  result ScanResult
}

func (o sslCheckOptions) rateLimit () {
  <-o.hostTicker.C
  <-o.globalTicker.C
}

func (o sslCheckOptions) testProtocolCipher (cipherName string) (string, error) {
  // fmt.Println("trying", s.host, cipherName)

  var handshake handShakeResult

  const request = "GET / HTTP/1.0\r\nUser-Agent: SSLScan\r\nHost: %s\r\n\r\n"

  //creates TLS context (SSL disabled by default)
  context, err := openssl.NewCtxWithVersion(openssl.TLSv1_2)
  check(err)

  err = context.SetCipherList ( cipherName )
  check(err)

  o.rateLimit()
  conn, err := net.DialTimeout("tcp", o.host, time.Duration(30)*time.Second)
  if err != nil {
    o.appendError(blockedDoS, err)
    return "", err
  }

  conn_ssl, err := openssl.Client(conn, context)
  check(err)
  err = conn_ssl.Handshake()  

  if err != nil {
    //inspect for weak dh key
    errorString := err.Error()
    //log.Println(errorString)
    if strings.Contains(errorString, "dh key too small") {
      o.appendError(dhKeyTooSmall, err)
    }
    if strings.Contains(errorString, "no such host") {
      o.appendError(invalidHostname, err)
      return "", err
    }
    if strings.Contains(errorString, "connection timed out") {
      o.appendError(timeout, err)
      return "", err
    }
    return "", nil
  }
  defer conn_ssl.Close()

  handshake.cipher, err = conn_ssl.CurrentCipher()
  check(err)

  cert, err := conn_ssl.PeerCertificate()
  check(err)

  pkey, err := cert.PublicKey()
  check(err)

  //FIX: PKeySize assumes RSA authentication
  handshake.authKeyBits = openssl.PKeySize(pkey) * 8

  //fmt.Println("Encryption Key Size (bits): ", key_size*8)

  //fmt.Sprintf("%s accepted cipher %s", s.host, sslCipherName)
  
  keyId, keyBits, curveName := conn_ssl.GetServerTmpKey()
  handshake.keyExchangeID = keyId
  handshake.keyExchangeBits = keyBits
  handshake.ecdheCurve = curveName
  fmt.Println(o.host, handshake.cipher, keyId, keyBits, curveName)
  o.result.handshakes = append(o.result.handshakes, handshake)
  return handshake.cipher, nil
}

func (o sslCheckOptions) testProtocolCiphers () {  

  //"RSA is an alias for kRSA" per 1.1.0 doc 
  //(wrongly described in 1.0.2 doc as RSA for either key exchange
  //or authentication)
  cipher, err := o.testProtocolCipher("kRSA")
  if err != nil {
    fmt.Println("Early fail on host ", o.host)
    return
  }
  if cipher != "" {
    o.result.keyExchangeMethods = append(o.result.keyExchangeMethods, rsaKeyExch)
  }

  //check for ECDHE key exchange support, deliberately eliminating anonmyous (kECDHE)
  cipher, err = o.testProtocolCipher("ECDHE")
  if err != nil {
    fmt.Println("Early fail on host ", o.host)
    return
  }
  if cipher != ""  {
    o.result.keyExchangeMethods = append(o.result.keyExchangeMethods, ecdhe)
  }

  //check for anonymous ECDHE
  cipher, err = o.testProtocolCipher("aECDHE")
  if err != nil {
    fmt.Println("Early fail on host ", o.host)
    return
  }
  if cipher != ""  {
    o.result.keyExchangeMethods = append(o.result.keyExchangeMethods, anonECDHE)
  }

  //check for fixed ECDH
  cipher, err = o.testProtocolCipher("kECDH")
  if err != nil {
    fmt.Println("Early fail on host ", o.host)
    return
  }
  if cipher != "" {
    o.result.keyExchangeMethods = append(o.result.keyExchangeMethods, fixedECDH)
  }

  //loop over DHE ciphers, including anonymous
  dheCipher := "kDHE"

  for true {
    cipher, _ = o.testProtocolCipher(dheCipher)
    if cipher != "" {
      dheCipher += ":" + cipher
    }else{
      break;
    }
  }

  fmt.Println(o.host, "Done")

  return
}

func (o sslCheckOptions) appendError (cE connectionError, e error) {
  o.result.error = append(o.result.error, cE)
  o.result.comments += e.Error() + "\n"
}

func (o sslCheckOptions) scanHost() {
  o.hostTicker = time.NewTicker(time.Second)

  //initial TCP connection to 443 port
  o.rateLimit()
  conn, err := net.DialTimeout("tcp", o.host, time.Duration(30)*time.Second)
  if err != nil {
    //TODO : fine-grain error check
    log.Print("Error in connection start to host", o.host, err)
    o.appendError(connectionRefused, err)
    if strings.HasPrefix(o.host, "www") {
      return
    }

    log.Print("Trying www prefix for host", o.host)
    o.host = "www." + o.host

    o.rateLimit()
    conn, err = net.DialTimeout("tcp", o.host, time.Duration(30)*time.Second)
    if err != nil {
      log.Print("Could not connect to host", o.host, err)
      o.appendError(connectionRefused, err)
      return
    }
  }
  conn.Close()

  o.testProtocolCiphers()
}