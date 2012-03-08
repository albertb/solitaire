// An implementation of the Solitaire cryptograhic algorithm, as designed by
// Bruce Schneier: http://www.schneier.com/solitaire.html

package main

import (
  "flag"
  "fmt"
  "log"
  "strings"
)

type card int

const (
  jokerA card = 53
  jokerB card = 54
)

func (c card) isJoker() bool {
  return c == jokerA || c == jokerB
}

func (c card) value() int {
  if c.isJoker() {
    return int(jokerA)  // Both jokers are worth 53
  }
  return int(c)
}

type Deck struct {
  cards []card
}

type InvalidCharacterError string

func (e InvalidCharacterError) Error() string {
  return "invalid character: '" + string(e) + "'"
}

func NewDeck(passphrase string) (*Deck, error) {
  var d Deck
  d.cards = make([]card, 54)
  for i:= 0; i < len(d.cards); i++ {
    d.cards[i] = card(i + 1)  // 1..52 followed by JokerA and JokerB
  }
  for _, c := range passphrase {
    if c < 'A' || c > 'Z' {
      return nil, InvalidCharacterError(c)
    }
    d.step()
    d.countCut(int(c + 1 - 'A'))
  }
  return &d, nil
}

// Reorders the deck, using pairs of |pos| as the ranges.
func (d *Deck) reorder(pos ...int) {
  tmp := make([]card, len(d.cards))[0:0]
  for i := 0; i + 1 < len(pos); i += 2 {
    start, end := pos[i], pos[i + 1]
    if start <= end {
      tmp = append(tmp, d.cards[start:end]...)
    }
  }
  d.cards = tmp
}

// Finds the |target| in the deck, returns its position.
func (d *Deck) find(target card) int {
  for i, c := range d.cards {
    if c == target {
      return i
    }
  }
  panic("card not found: " + string(target) + "'")
}

// Moves down the card at position |pos|, |off| places down.
func (d *Deck) moveDown(pos, off int) {
  for i := 0; i < off; i++ {
    if pos + 1 == len(d.cards) {
      d.reorder(0, 1, 53, 54, 1, 53)
      pos = 1
    } else {
      d.cards[pos], d.cards[pos + 1] = d.cards[pos + 1], d.cards[pos]
      pos += 1
    }
  }
}

// Move the jokers down.
func (d *Deck) moveJokers() {
  a := d.find(jokerA)
  d.moveDown(a, 1)

  b := d.find(jokerB)
  d.moveDown(b, 2)
}

// Triple cuts the deck around the jokers.
func (d *Deck) tripleCut() {
  a, b := d.find(jokerA), d.find(jokerB)
  if a > b {
    a, b = b, a
  }
  b += 1
  d.reorder(b, 54, a, b, 0, a)
}

// Count cuts the deck around the card at position |count|.
func (d *Deck) countCut(count int) {
  d.reorder(count, 53, 0, count, 53, 54)
}

// Does one step of the key algorithm.
func (d *Deck) step() {
  d.moveJokers()
  d.tripleCut()
  d.countCut(d.cards[53].value())
}

// Returns the next output value.
func (d *Deck) output() int {
  d.step()
  count := d.cards[0]
  output := d.cards[count.value()]
  if output.isJoker() {
    return d.output()  // Never use a joker as the output card.
  }
  return output.value()
}

// Processes |message| with the solitaire cipher.
func (d *Deck) addToKeystream(message string, decrypt bool) (string, error) {
  var keyed string
  for i, c := range message {
    if c < 'A' || c > 'Z' {
      return "", InvalidCharacterError(c)
    }

    if i > 0 && i % 5 == 0 {
      keyed += " "
    }

    output := d.output()
    if decrypt {
      output = 52 - output
    }
    keyed += string('A' + (int(c) - 'A' + output) % 26)
  }
  return keyed, nil
}

func (d *Deck) Encrypt(plaintext string) (string, error) {
  if len(plaintext) % 5 != 0 {  // Pad the plaintext with Xs.
    plaintext +=  strings.Repeat("X", 5 - (len(plaintext) % 5))
  }
  return d.addToKeystream(plaintext, false)
}

func (d *Deck) Decrypt(ciphertext string) (string, error) {
  return d.addToKeystream(ciphertext, true)
}

var decrypt *bool = flag.Bool("d", false, "whether to decrypt")

func format(input string) string {
  return strings.ToUpper(strings.Replace(input, " ", "", -1))
}

func main() {
  flag.Parse()
  passphrase := format(flag.Arg(0))
  message := format(flag.Arg(1))

  d, err := NewDeck(passphrase)
  if err != nil {
    log.Fatal("failed to initialize deck: ", err)
  }

  if *decrypt {
    plaintext, err := d.Decrypt(string(message))
    if err != nil {
      log.Fatal("failed to decrypt: ", err)
    }
    fmt.Println(plaintext)
  } else {
    ciphertext, err := d.Encrypt(string(message))
    if err != nil {
      log.Fatal("failed to encrypt: ",  err)
    }
    fmt.Println(ciphertext)
  }
}
