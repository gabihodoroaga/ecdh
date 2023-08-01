package ed25519

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSharedSecret(t *testing.T) {

	alicePrivKey,_ := hex.DecodeString("8099218df05be91769679587124cfb3c1f6b0602805ffda193f26790c531e1eb")
	alicePubKey,_ := hex.DecodeString("fef1ed54588c4edc73e6c1320d7c67c886f72caeb24e2c072e4aeb1c2be1edab")

	bobPrivKey,_ := hex.DecodeString("8ed0ce08849ef03657e0f137f15b73afbfc4ecbfcc76505e5fb5f63c998bb8a0")
	bobPubKey,_ := hex.DecodeString("584db3b049decbcee583e051e2d9f205ae516597b3adb3f98806a19c6c05ad62")

	aliceSecret, err := SharedSecret(bobPubKey, alicePrivKey)
	require.Nil(t, err)
	require.NotNil(t, aliceSecret)

	bobSecret, err := SharedSecret(alicePubKey, bobPrivKey)
	require.Nil(t, err)
	require.NotNil(t, bobSecret)

	assert.Equal(t, aliceSecret, bobSecret)
}
