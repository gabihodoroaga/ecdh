package sr25519

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)


func TestSharedSecret(t *testing.T) {

	alicePrivKey,_ := hex.DecodeString("4371abacb33d4819e69ae66cb120a10a2403645926f9def758577278b39b43d3")
	alicePubKey,_ := hex.DecodeString("32bc4936c7925bfc8f7305b1672235254cdf9f0589474e06351365e461558d31")

	bobPrivKey,_ := hex.DecodeString("b38d9ec4180312196f474fd36cc2919b121bafe9bb5185d86a3f97021e665177")
	bobPubKey,_ := hex.DecodeString("de372a0e94cc1f2c3e5ec27742c9a6011f3823c2e98f091d04c2899586d00d47")

	aliceSecret, err := SharedSecret(bobPubKey, alicePrivKey)
	require.Nil(t, err)
	require.NotNil(t, aliceSecret)

	bobSecret, err := SharedSecret(alicePubKey, bobPrivKey)
	require.Nil(t, err)
	require.NotNil(t, bobSecret)

	assert.Equal(t, aliceSecret, bobSecret)
}