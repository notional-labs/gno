package keys

import (
	"fmt"
	"path/filepath"
)

const defaultKeyDBName = "keys"

// NewKeyBaseFromDir initializes a keybase at a particular dir.
func NewKeyBaseFromDir(rootDir string) (Keybase, error) {
	return NewLazyDBKeybase(defaultKeyDBName, filepath.Join(rootDir, "data")), nil
}

// NewInMemoryKeyBase returns a storage-less keybase.
func NewInMemoryKeyBase() Keybase { return NewInMemory() }

func ValidateMultisigThreshold(k, nKeys int) error {
	if k <= 0 {
		return fmt.Errorf("threshold must be a positive integer")
	}
	if nKeys < k {
		return fmt.Errorf(
			"threshold k of n multisignature: %d < %d", nKeys, k)
	}
	return nil
}

// // 48 words mnemonic is for ed25519 key gen
// func Split48WordsMnemonic(mnemonic string) (string, string) {
// 	wordListFromMnemonic := strings.Fields(mnemonic)
// 	mnemonic1 := strings.Join(wordListFromMnemonic[:24], " ")
// 	mnemonic2 := strings.Join(wordListFromMnemonic[24:], " ")
// 	return mnemonic1, mnemonic2
// }

// func Convert48WordsMnemonicToByte(mnemonic string) ([]byte, error) {
// 	mnemonic1, mnemonic2 := Split48WordsMnemonic(mnemonic)
// 	bz1, err := bip39.MnemonicToByteArray(mnemonic1)
// 	if err != nil {
// 		return nil, err
// 	}
// 	bz2, err := bip39.MnemonicToByteArray(mnemonic2)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return append(bz1[:], bz2[:]...), nil
// }

// func Convert512BytesToMnemonic(bz []byte) (string, error) {
// 	entropySeed1 := bz[:32]
// 	entropySeed2 := bz[32:]
// 	mnemonic1, err := bip39.NewMnemonic(entropySeed1[:])
// 	if err != nil {
// 		return "", err
// 	}
// 	mnemonic2, err := bip39.NewMnemonic(entropySeed2[:])
// 	if err != nil {
// 		return "", err
// 	}
// 	mnemonic := mnemonic1 + " " + mnemonic2
// 	return mnemonic, nil
// }
