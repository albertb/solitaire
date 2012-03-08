package main

import (
  "strings"
  "testing"
)

type CipherTest struct {
  plaintext string
  passphrase string
  ciphertext string
}

var cipherTests = []CipherTest {
  { "AAAAAAAAAA", "", "EXKYI ZSGEH" },
  { "AAAAAAAAAAAAAAA", "F", "XYIUQ BMHKK JBEGY" },
  { "AAAAAAAAAAAAAAA", "FO", "TUJYM BERLG XNDIW" },
  { "AAAAAAAAAAAAAAA", "FOO", "ITHZU JIWGR FARMW" },
  { "AAAAAAAAAAAAAAA", "A", "XODAL GSCUL IQNSC" },
  { "AAAAAAAAAAAAAAA", "AA", "OHGWM XXCAI MCIQP" },
  { "AAAAAAAAAAAAAAA", "AAA", "DCSQY HBQZN GDRUT" },
  { "AAAAAAAAAAAAAAA", "B", "XQEEM OITLZ VDSQS" },
  { "AAAAAAAAAAAAAAA", "BC", "QNGRK QIHCL GWSCE" },
  { "AAAAAAAAAAAAAAA", "BCD", "FMUBY BMAXH NQXCJ" },
  { "AAAAAAAAAAAAAAAAAAAAAAAAA", "CRYPTONOMICON", "SUGSR SXSWQ RMXOH IPBFP XARYQ" },
  { "SOLITAIRE", "CRYPTONOMICON", "KIRAK SFJAN" },
}

func TestEncrypt(t *testing.T) {
  for i, ct := range cipherTests {
    d, err := NewDeck(ct.passphrase)
    if err != nil {
      t.Errorf("NewDeck(%s) = %s", ct.passphrase, err)
      continue
    }

    ciphertext, err := d.Encrypt(ct.plaintext)
    if err != nil {
      t.Errorf("Deck.Encrypt %d = %s", i, err)
      continue
    }

    if ciphertext != ct.ciphertext {
      t.Errorf("Deck.Encrypt %d = %s, want %s.", i, ciphertext, ct.ciphertext)
      continue
    }
  }
}

func TestDecrypt(t *testing.T) {
  for i, ct := range cipherTests {
    d, err := NewDeck(ct.passphrase)
    if err != nil {
      t.Errorf("NewDeck(%s) = %s", ct.passphrase, err)
      continue
    }

    ciphertext := strings.Replace(ct.ciphertext, " ", "", -1)
    plaintext, err := d.Decrypt(ciphertext)
    if err != nil {
      t.Errorf("Deck.Decrypt %d = %s", i, err)
      continue
    }
    plaintext = strings.Replace(plaintext, " ", "", -1)

    expected := ct.plaintext
    if len(expected) % 5 != 0 {
      expected += strings.Repeat("X", 5 - (len(expected) % 5))
    }

    if plaintext != expected {
      t.Errorf("Deck.Decrypt %d = %s, want %s.", i, plaintext, expected)
      continue
    }
  }
}
