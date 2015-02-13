package sha3

import (
	"github.com/dedis/crypto/test"
	"testing"
)

func TestAES(t *testing.T) {
	test.BlockCipherTest(t, NewCipher224)
}
