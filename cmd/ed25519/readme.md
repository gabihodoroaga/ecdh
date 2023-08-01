# Encrypt using ed25519 keys

Generate a key pair

```bash
docker run -it --rm parity/subkey generate --scheme Ed25519
```


Encrypt/Decrypt

```bash
message="Test"
echo "Message to encrypt: $message"
encMessage=$(go run main.go -e -key "fef1ed54588c4edc73e6c1320d7c67c886f72caeb24e2c072e4aeb1c2be1edab" -m $message)
echo "Encrypted message in hex: $encMessage"
decMessage=$(go run main.go -d -key "8099218df05be91769679587124cfb3c1f6b0602805ffda193f26790c531e1eb" -m $encMessage)
echo "Decrypted message: $decMessage"
```

