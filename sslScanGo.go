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
    "errors"
    // "fmt"
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

func (o *sslCheckOptions) testProtocolCipher (cipherName string) (string, error) {
  // fmt.Println("trying", s.host, cipherName)

  var handshake HandShakeResult

  const request = "GET / HTTP/1.0\r\nUser-Agent: SSLScan\r\nHost: %s\r\n\r\n"

  //creates TLS context (SSL disabled by default)
  context, err := openssl.NewCtxWithVersion(openssl.TLSv1_2)
  check(err)

  err = context.SetCipherList ( cipherName )
  check(err)

  o.rateLimit()
  conn, err := openssl.Dial("tcp", o.host, context, 0)
  // conn, err := net.DialTimeout("tcp", o.host, time.Duration(30)*time.Second)
  // if err != nil {
  //   o.appendError(blockedDoS, err)
  //   return "", err
  // }

  // conn_ssl, err := openssl.Client(conn, context)
  // check(err)
  // err = conn_ssl.Handshake()  

  if err != nil {
    //inspect for weak dh key
    errorString := err.Error()
    //log.Println(errorString)
    if strings.Contains(errorString, "dh key too small") {
      o.appendError(dhKeyTooSmall, err)
    }
    if strings.Contains(errorString, "connection timed out") {
      o.appendError(timeout, err)
    }
    return "", err
  }
  defer conn.Close()

  handshake.Cipher, err = conn.CurrentCipher()
  check(err)
  // fmt.Printf("%s cipher: %s\n", o.host, handshake.Cipher)

  tmpKeyId, tmpKeyBits, tmpKeyCurveName := conn.GetServerTmpKey()
  handshake.KeyExchangeID = tmpKeyId
  handshake.KeyExchangeBits = tmpKeyBits
  handshake.KeyExchangeCurve = tmpKeyCurveName
  

  // fmt.Printf("Tmp key: 0x%x, %d, %s\n",  tmpKeyId, tmpKeyBits, tmpKeyCurveName)
    switch tmpKeyId {
    case int(C.EVP_PKEY_DH):
      o.result.KeyExchangeMethods |= dhe
    case int(C.EVP_PKEY_EC):
      o.result.KeyExchangeMethods |= ecdhe
    }
  //todo: check for fixed DH

  cert, err := conn.PeerCertificate()
  check(err)
  pkey, err := cert.PublicKey()

  if pkey == nil { // no key found, must be anonymous
    o.result.AuthMethods ^= anonymous
    if tmpKeyId == 0 {
      noCipherError := errors.New("No Public Key or Server Tmp Key found")
      o.appendError(other, noCipherError)
    }

  }else{
    certKeyId, certKeyBits, certCurveName := openssl.GetPKeyParameters(pkey)
    // fmt.Printf("Cert 0x%x, %d, %s\n",  certKeyId, certKeyBits, certCurveName)
    switch certKeyId {
    case int(C.EVP_PKEY_RSA):
      o.result.AuthMethods |= rsaAuth
    case int(C.EVP_PKEY_DSA):
      o.result.AuthMethods |= dsa
    case int(C.EVP_PKEY_EC):
      o.result.AuthMethods |= ec
    }

    handshake.AuthKeyId = certKeyId
    handshake.AuthKeyBits = certKeyBits
    handshake.AuthKeyCurve = certCurveName

    if tmpKeyId == 0 {
      o.result.KeyExchangeMethods |= rsaKeyExch
      handshake.KeyExchangeID = certKeyId
      handshake.KeyExchangeBits = certKeyBits
      handshake.KeyExchangeCurve = certCurveName
    } else if handshake.KeyExchangeBits < handshake.AuthKeyBits && handshake.KeyExchangeCurve == "" {
      o.appendError(dhRSAmismatch, nil)
    }
  }

  o.result.Handshakes = append(o.result.Handshakes, handshake)
  return handshake.Cipher, nil  
  
}

func (o *sslCheckOptions) testProtocolCiphers () {  

  //loop over DHE ciphers, including anonymous
  dheCipher := "ALL:COMPLEMENTOFALL"

  for true {
    //fmt.Print(dheCipher)
    cipher, _ := o.testProtocolCipher(dheCipher)
    if cipher != "" {
      dheCipher += ":!" + cipher
    }else{
      break;
    }
  }

  //fmt.Println(o.host, "Done")

  return
}

func (o *sslCheckOptions) appendError (cE ConnectionError, e error) {
  //o.result.Error = append(o.result.Error, cE)
  //o.result.Comments += e.Error() + "\n"
  //inspect for weak dh key
  if e == nil {
    o.result.Error = append(o.result.Error, cE)
    return
  }
  errorString := e.Error()
  if strings.Contains(errorString, "no such host") {
    o.result.Error = append (o.result.Error, invalidHostname)
    o.result.Comments += e.Error() + "\n"
  } else if strings.Contains(errorString, "i/o timeout") {
    o.result.Error = append (o.result.Error, timeout)
    o.result.Comments += e.Error() + "\n"
  } else {
    o.result.Error = append(o.result.Error, cE)
    o.result.Comments += e.Error() + "\n"
  }
}

func (o *sslCheckOptions) scanHost() {
  o.hostTicker = time.NewTicker(time.Second)

  //initial TCP connection to 443 port
  o.rateLimit()
  conn, err := net.DialTimeout("tcp", o.host, time.Duration(30)*time.Second)
  if err != nil {
    //TODO : fine-grain error check
    log.Println("Error in connection start to host ", o.host, err)
    o.appendError(connectionRefused, err)
    if strings.HasPrefix(o.host, "www") {
      return
    }

    log.Println("Trying www prefix for host", o.host)
    o.host = "www." + o.host

    o.rateLimit()
    conn, err = net.DialTimeout("tcp", o.host, time.Duration(30)*time.Second)
    if err != nil {
      log.Println("Could not connect to host", o.host, err)
      o.appendError(connectionRefused, err)
      return
    }
  }
  conn.Close()

  o.testProtocolCiphers()
}