package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ChunkSize is the plaintext size of one blob chunk.
const ChunkSize = 1 << 20

// Overhead is the number of bytes AES-GCM adds to every sealed message (nonce + tag).
const Overhead = 12 + 16

// ErrDecrypt is returned when a ciphertext cannot be decrypted: wrong key or tampered data.
var ErrDecrypt = errors.New("crypto: decryption failed")

// Cipher encrypts and authenticates data with AES-256-GCM.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher creates a cipher from a 32-byte key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto: key must be %d bytes", KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Seal encrypts plaintext and binds it to aad. The result is nonce || ciphertext || tag.
func (c *Cipher) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize(), c.aead.NonceSize()+len(plaintext)+c.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: generate nonce: %w", err)
	}
	return c.aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Open decrypts a message produced by Seal with the same aad.
func (c *Cipher) Open(sealed, aad []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	if len(sealed) < ns+c.aead.Overhead() {
		return nil, ErrDecrypt
	}
	plain, err := c.aead.Open(nil, sealed[:ns], sealed[ns:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}

// chunkAAD binds a chunk to its blob, position and to the "last chunk" flag,
// so chunks cannot be reordered, moved between blobs or truncated.
func chunkAAD(blobID []byte, index uint64, last bool) []byte {
	aad := make([]byte, 0, len(blobID)+9)
	aad = append(aad, blobID...)
	aad = binary.BigEndian.AppendUint64(aad, index)
	if last {
		return append(aad, 1)
	}
	return append(aad, 0)
}

// EncryptStream reads r in ChunkSize pieces, encrypts every piece and passes it to emit.
// It returns the number of plaintext bytes read. An empty input produces one empty chunk.
func (c *Cipher) EncryptStream(r io.Reader, blobID []byte, emit func(chunk []byte) error) (int64, error) {
	cur := make([]byte, ChunkSize)
	next := make([]byte, ChunkSize)
	n, err := io.ReadFull(r, cur)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return 0, fmt.Errorf("crypto: read: %w", err)
	}
	var total int64
	for index := uint64(0); ; index++ {
		m := 0
		if n == ChunkSize {
			m, err = io.ReadFull(r, next)
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				return total, fmt.Errorf("crypto: read: %w", err)
			}
		}
		last := m == 0
		sealed, err := c.Seal(cur[:n], chunkAAD(blobID, index, last))
		if err != nil {
			return total, err
		}
		if err := emit(sealed); err != nil {
			return total, err
		}
		total += int64(n)
		if last {
			return total, nil
		}
		cur, next = next, cur
		n = m
	}
}

// DecryptStream decrypts chunks produced by EncryptStream and writes the plaintext to w.
// next must return io.EOF after the last chunk. A stream without its final chunk is rejected.
func (c *Cipher) DecryptStream(next func() ([]byte, error), blobID []byte, w io.Writer) (int64, error) {
	var total int64
	pending, err := next()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0, fmt.Errorf("%w: empty stream", ErrDecrypt)
		}
		return 0, err
	}
	for index := uint64(0); ; index++ {
		following, err := next()
		last := errors.Is(err, io.EOF)
		if err != nil && !last {
			return total, err
		}
		plain, err := c.Open(pending, chunkAAD(blobID, index, last))
		if err != nil {
			return total, fmt.Errorf("%w: chunk %d", ErrDecrypt, index)
		}
		if _, err := w.Write(plain); err != nil {
			return total, fmt.Errorf("crypto: write: %w", err)
		}
		total += int64(len(plain))
		if last {
			return total, nil
		}
		pending = following
	}
}
