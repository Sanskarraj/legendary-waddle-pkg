package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	ROUNDS     = 20
	BLOCK_SIZE = 64 // ChaCha20 block size in bytes
)

var (
	NONCE   = [8]byte{0, 0, 0, 0, 0, 0, 0, 0} // Set a constant nonce value
	COUNTER uint32 = 0                        // Set a constant counter value
)

func chacha20Encrypt(key []byte, message []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("Key must be 32 bytes long")
	}

	ciphertext := make([]byte, 0, len(message))
	for i := 0; i < len(message); i += BLOCK_SIZE {
		end := i + BLOCK_SIZE
		if end > len(message) {
			end = len(message)
		}
		chunk := message[i:end]

		keystreamBlock, err := chacha20Block(key, NONCE[:], COUNTER+uint32(i/BLOCK_SIZE))
		if err != nil {
			return nil, err
		}

		encryptedChunk := make([]byte, len(chunk))
		for j := range chunk {
			encryptedChunk[j] = chunk[j] ^ keystreamBlock[j]
		}
		ciphertext = append(ciphertext, encryptedChunk...)
	}

	return ciphertext, nil
}

// chacha20Decrypt is identical to chacha20Encrypt due to the nature of the XOR operation
func chacha20Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	return chacha20Encrypt(key, ciphertext)
}

func chacha20Block(key []byte, nonce []byte, counter uint32) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("Key must be 32 bytes long")
	}

	state := [16]uint32{
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // Constants
	}

	// Add key to state
	for i := 0; i < 8; i++ {
		state[4+i] = binary.LittleEndian.Uint32(key[i*4 : (i+1)*4])
	}

	// Add counter and nonce to state
	state[12] = counter
	state[13] = binary.LittleEndian.Uint32(nonce[0:4])
	state[14] = binary.LittleEndian.Uint32(nonce[4:8])

	initialState := state

	// Perform 20 rounds of the ChaCha20 core function
	for i := 0; i < ROUNDS; i++ {
		// Column round
		quarterRound(&state, 0, 4, 8, 12)
		quarterRound(&state, 1, 5, 9, 13)
		quarterRound(&state, 2, 6, 10, 14)
		quarterRound(&state, 3, 7, 11, 15)
		// Diagonal round
		quarterRound(&state, 0, 5, 10, 15)
		quarterRound(&state, 1, 6, 11, 12)
		quarterRound(&state, 2, 7, 8, 13)
		quarterRound(&state, 3, 4, 9, 14)
	}

	// Add the initial state to the final state
	for i := 0; i < 16; i++ {
		state[i] += initialState[i]
	}

	// Convert state to bytes
	output := make([]byte, 64)
	for i, v := range state {
		binary.LittleEndian.PutUint32(output[i*4:], v)
	}

	return output, nil
}

func quarterRound(state *[16]uint32, a, b, c, d int) {
	state[a] += state[b]
	state[d] ^= state[a]
	state[d] = (state[d] << 16) | (state[d] >> 16)

	state[c] += state[d]
	state[b] ^= state[c]
	state[b] = (state[b] << 12) | (state[b] >> 20)

	state[a] += state[b]
	state[d] ^= state[a]
	state[d] = (state[d] << 8) | (state[d] >> 24)

	state[c] += state[d]
	state[b] ^= state[c]
	state[b] = (state[b] << 7) | (state[b] >> 25)
}

func main() {
	key := []byte("kZGs6njBT6OsXZCFlb62I88fc5AireQh")
	message := []byte("Hello World!")

	ciphertext, err := chacha20Encrypt(key, message)
	if err != nil {
		fmt.Printf("Encryption Error: %v\n", err)
		return
	}

	fmt.Printf("Ciphertext: %x\n", ciphertext)

	expectedCiphertext := "b603acfb461cef3064c2b834"

	if fmt.Sprintf("%x", ciphertext) == expectedCiphertext {
		fmt.Println("The output matches the expected ciphertext.")
	} else {
		fmt.Println("The output does not match the expected ciphertext.")
	}

	// Decryption
	decrypted, err := chacha20Decrypt(key, ciphertext)
	if err != nil {
		fmt.Printf("Decryption Error: %v\n", err)
		return
	}

	fmt.Printf("Decrypted message: %s\n", decrypted)
	if string(decrypted) == string(message) {
		fmt.Println("Decryption successful: The decrypted message matches the original message.")
	} else {
		fmt.Println("Decryption failed: The decrypted message does not match the original message.")
	}
}