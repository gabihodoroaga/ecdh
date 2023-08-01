# Encrypt using sr25519 keys

Generate a key pair

```bash
docker run -it --rm parity/subkey generate --scheme Sr25519
```


Encrypt/Decrypt

```bash
message="Test"
echo "Message to encrypt: $message"
encMessage=$(go run main.go -e -key "32bc4936c7925bfc8f7305b1672235254cdf9f0589474e06351365e461558d31" -m $message)
echo "Encrypted message in hex: $encMessage"
decMessage=$(go run main.go -d -key "4371abacb33d4819e69ae66cb120a10a2403645926f9def758577278b39b43d3" -m $encMessage)
echo "Decrypted message: $decMessage"
```


