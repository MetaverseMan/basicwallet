package main

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"io/ioutil"
	"math/big"
	"path/filepath"
)

type HDKeyStore struct {
	KeysDirPath     string
	ScryptN         int
	ScryptP         int
	privateKeyECDSA *ecdsa.PrivateKey
}

func NewKeyFromECDSA(privateKeyECDSA *ecdsa.PrivateKey) *keystore.Key {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil
	}
	key := &keystore.Key{
		Id:         id,
		Address:    crypto.PubkeyToAddress(privateKeyECDSA.PublicKey),
		PrivateKey: privateKeyECDSA,
	}
	return key
}
func NewHDKeyStore(dirPath string) *HDKeyStore {
	return &HDKeyStore{
		KeysDirPath:     dirPath,
		ScryptN:         keystore.LightScryptN,
		ScryptP:         keystore.LightScryptP,
		privateKeyECDSA: nil,
	}
}
func (ks *HDKeyStore) StoreKey(filename string, key *keystore.Key, auth string) error {
	encryptKey, err := keystore.EncryptKey(key, auth, ks.ScryptN, ks.ScryptP)
	if err != nil {
		return err
	}
	return writeKeyFile(filename, encryptKey)
}
func (ks *HDKeyStore) JoinPath(filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	}
	return filepath.Join(ks.KeysDirPath, filename)
}
func (ks *HDKeyStore) GetKey(addr common.Address, filename, auth string) (*keystore.Key, error) {
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	key, err := keystore.DecryptKey(file, auth)
	if err != nil {
		return nil, err
	}
	if key.Address != addr {
		return nil, fmt.Errorf("key content mismatch: have account %x, want %x", key.Address, addr)
	}
	ks.privateKeyECDSA = key.PrivateKey
	return key, nil
}
func (ks *HDKeyStore) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	fmt.Printf("%#v \n ", ks)
	signTx, err := types.SignTx(tx, types.HomesteadSigner{}, ks.privateKeyECDSA)
	if err != nil {
		return nil, err
	}
	message, err := signTx.AsMessage(types.HomesteadSigner{}, nil)
	if err != nil {
		return nil, err
	}
	if message.From() != account.Address {
		return nil, fmt.Errorf("signer mismatch: expected %s, got %s", account.Address.Hex(), message.From().Hex())
	}
	return signTx, nil

}
