package main

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
	"math/big"
	"math/rand"
	"sync"
)

// DefaultRootDerivationPath is the root path to which custom derivation endpoints
// are appended. As such, the first account will be at m/44'/60'/0'/0, the second
// at m/44'/60'/0'/1, etc.
var DefaultRootDerivationPath = accounts.DefaultRootDerivationPath

// DefaultBaseDerivationPath is the base path from which custom derivation endpoints
// are incremented. As such, the first account will be at m/44'/60'/0'/0, the second
// at m/44'/60'/0'/1, etc
var DefaultBaseDerivationPath = accounts.DefaultBaseDerivationPath

type Wallet struct {
	mnemonic  string
	masterKey *hdkeychain.ExtendedKey
	seed      []byte
	url       accounts.URL
	paths     map[common.Address]accounts.DerivationPath
	accounts  []accounts.Account
	stateLock sync.RWMutex
}

func newWallet(seed []byte) (*Wallet, error) {
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {

	}
	return &Wallet{
		masterKey: masterKey,
		seed:      seed,
		accounts:  []accounts.Account{},
		paths:     map[common.Address]accounts.DerivationPath{},
	}, nil
}
func NewFromMnemonic(mnemonic, password string) (*Wallet, error) {
	if mnemonic == "" {
		return nil, errors.New("mnemonic is required")
	}
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("mnemonic is invalid")
	}
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, password)
	if err != nil {
		return nil, err
	}
	wallet, err := newWallet(seed)
	if err != nil {
		return nil, err
	}
	wallet.mnemonic = mnemonic
	return wallet, nil
}
func NewFromSeed(seed []byte) (*Wallet, error) {
	if len(seed) != 0 {
		return nil, errors.New("seed is required")
	}
	return newWallet(seed)
}
func (w *Wallet) URL() accounts.URL {
	return w.url
}
func (w *Wallet) Status() (string, error) {
	return "ok", nil
}
func (w *Wallet) Open(passphrase string) error {
	return nil
}
func (w *Wallet) Close() error {
	return nil
}
func (w *Wallet) Contains(account accounts.Account) bool {
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()
	_, exists := w.paths[account.Address]
	return exists
}

func (w *Wallet) Unpin(account accounts.Account) error {
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()
	for i, acct := range w.accounts {
		if acct.Address.String() == account.Address.String() {
			w.accounts = removeAtIndex(w.accounts, i)
			delete(w.paths, account.Address)
			return nil
		}
	}
	return errors.New("account not found")
}
func (w *Wallet) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	w.stateLock.RLock()
	address, err := w.deriveAddress(path)
	w.stateLock.RUnlock()

	if err != nil {
		return accounts.Account{}, err
	}

	account := accounts.Account{
		Address: address,
		URL: accounts.URL{
			Scheme: "",
			Path:   path.String(),
		},
	}
	if !pin {
		return account, nil
	}
	w.stateLock.Lock()
	defer w.stateLock.RUnlock()
	if _, ok := w.paths[address]; !ok {
		w.accounts = append(w.accounts, account)
		w.paths[address] = path
	}
	return account, nil
}

// SelfDerive implements accounts.Wallet, trying to discover accounts that the
// user used previously (based on the chain state), but ones that he/she did not
// explicitly pin to the wallet manually. To avoid chain head monitoring, self
// derivation only runs during account listing (and even then throttled).
func (w *Wallet) SelfDerive(base accounts.DerivationPath, chain ethereum.ChainStateReader) {
	// TODO: self derivation
}
func (w *Wallet) derivePrivateKey(path accounts.DerivationPath, masterKey *hdkeychain.ExtendedKey) (*ecdsa.PrivateKey, error) {
	var err error
	key := masterKey
	for _, n := range path {
		//按照路径迭代获得最终key
		key, err = key.Derive(n)
		if err != nil {
			return nil, err
		}
	}
	//私钥
	privKey, err := key.ECPrivKey()
	PrivateKeyECDSA := privKey.ToECDSA()
	if err != nil {
		return nil, err
	}
	return PrivateKeyECDSA, nil
}
func (w *Wallet) DerivePrivateKey(path accounts.DerivationPath) (*ecdsa.PrivateKey, error) {
	var err error
	key := w.masterKey
	for _, n := range path {
		//按照路径迭代获得最终key
		key, err = key.Derive(n)
		if err != nil {
			return nil, err
		}
	}
	//私钥
	privKey, err := key.ECPrivKey()
	PrivateKeyECDSA := privKey.ToECDSA()
	if err != nil {
		return nil, err
	}
	return PrivateKeyECDSA, nil
}
func (w *Wallet) DerivePublicKey(path accounts.DerivationPath) (*ecdsa.PublicKey, error) {
	privateKeyECDSA, err := w.DerivePrivateKey(path)
	if err != nil {
		return nil, err
	}
	publickey := privateKeyECDSA.Public()
	publicKeyECDSA, ok := publickey.(*ecdsa.PublicKey)
	if !ok {
		return nil, err
	}
	return publicKeyECDSA, nil

}
func (w *Wallet) derivePublicKey(privateKey *ecdsa.PrivateKey) (*ecdsa.PublicKey, error) {
	publicKey := privateKey.Public()
	key := publicKey.(*ecdsa.PublicKey)
	return key, nil
}

func (w *Wallet) SignHash(account accounts.Account, hash []byte) ([]byte, error) {
	path := w.paths[account.Address]
	privateKey, err := w.DerivePrivateKey(path)
	if err != nil {
		return nil, err
	}
	return crypto.Sign(hash, privateKey)
}
func (w *Wallet) SignTx(account accounts.Account, tx *types.Transaction, chainId *big.Int) (*types.Transaction, error) {
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()
	path := w.paths[account.Address]
	privateKey, err := w.DerivePrivateKey(path)
	if err != nil {
		return nil, err
	}
	signedTx, err := types.SignTx(tx, types.HomesteadSigner{}, privateKey)
	if err != nil {
		return nil, err
	}

	message, err := signedTx.AsMessage(types.HomesteadSigner{}, nil)
	if err != nil {
		return nil, err
	}
	sender := message.From()
	if sender != account.Address {
		return nil, errors.New(fmt.Sprintf("signer mismatch: expected %s,got %s", account.Address.Hex(), sender.Hex()))
	}
	return signedTx, nil
}

//不用passphrase 不鸡肋吗？
func (w *Wallet) SignHashWithPassphrase(account accounts.Account, passphrase string, hash []byte) ([]byte, error) {
	return w.SignHash(account, hash)
}
func (w *Wallet) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainId *big.Int) (*types.Transaction, error) {
	return w.SignTx(account, tx, chainId)
}
func (w *Wallet) PrivateKey(account accounts.Account) (*ecdsa.PrivateKey, error) {
	path, err := accounts.ParseDerivationPath(account.URL.Path)
	if err != nil {
		return nil, err
	}
	return w.DerivePrivateKey(path)
}
func (w *Wallet) PrivateKeyBytes(account accounts.Account) ([]byte, error) {
	privateKey, err := w.PrivateKey(account)
	if err != nil {
		return nil, err
	}
	return crypto.FromECDSA(privateKey), nil
}
func (w *Wallet) PrivateKeyHex(account accounts.Account) (string, error) {
	privateKeyBytes, err := w.PrivateKeyBytes(account)
	if err != nil {
		return "", err
	}
	return hexutil.Encode(privateKeyBytes)[2:], nil
}

func (w *Wallet) PublicKey(account accounts.Account) (*ecdsa.PublicKey, error) {
	path, err := accounts.ParseDerivationPath(account.URL.Path)
	if err != nil {
		return nil, err
	}
	return w.DerivePublicKey(path)
}
func (w *Wallet) PublicKeyBytes(account accounts.Account) ([]byte, error) {
	publicKey, err := w.PublicKey(account)
	if err != nil {
		return nil, err
	}
	return crypto.FromECDSAPub(publicKey), nil
}
func (w *Wallet) PublicKeyHex(account accounts.Account) (string, error) {
	publicKeyBytes, err := w.PublicKeyBytes(account)
	if err != nil {
		return "", err
	}
	//todo 为啥是4
	return hexutil.Encode(publicKeyBytes)[4:], nil
}
func (w *Wallet) Address(account accounts.Account) (common.Address, error) {
	publicKey, err := w.PublicKey(account)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*publicKey), nil
}
func (w *Wallet) AddressBytes(account accounts.Account) ([]byte, error) {
	address, err := w.Address(account)
	if err != nil {
		return nil, err
	}
	return address.Bytes(), nil
}
func (w *Wallet) AddressHex(account accounts.Account) (string, error) {
	address, err := w.Address(account)
	if err != nil {
		return "", err
	}
	return address.Hex(), nil
}
func (w *Wallet) Path(account accounts.Account) (string, error) {
	return account.URL.Path, nil
}
func ParseDerivationPath(path string) accounts.DerivationPath {
	derivationPath, err := accounts.ParseDerivationPath(path)
	if err != nil {
		return nil
	}
	return derivationPath
}
func NewMnemonic(bits int) (string, error) {
	entropy, err := bip39.NewEntropy(bits)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}
func NewSeed() ([]byte, error) {
	b := make([]byte, 64)
	_, err := rand.Read(b)
	return b, err
}
func NewSeedFromMnemonic(mnemonic, password string) ([]byte, error) {
	if mnemonic == "" {
		return nil, errors.New("mneonic is required")
	}
	return bip39.NewSeedWithErrorChecking(mnemonic, password)
}
func (w *Wallet) deriveAddress(path accounts.DerivationPath) (common.Address, error) {
	key, err := w.DerivePublicKey(path)
	if err != nil {
		return common.Address{}, err
	}
	address := crypto.PubkeyToAddress(*key)
	return address, nil
}
func removeAtIndex(accts []accounts.Account, index int) []accounts.Account {
	return append(accts[:index], accts[index+1:]...)
}
