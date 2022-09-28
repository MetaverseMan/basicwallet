package main

import (
	"fmt"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

func main() {
	test_mnemonic()
}

func test_mnemonic() {
	//生成entropy
	entropy, err := bip39.NewEntropy(128)
	if err != nil {

	}
	//利用生成的entropy生成助记词
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {

	}

	fmt.Println(mnemonic)
	// Generate a Bip32 HD wallet for the mnemonic and a user supplied password
	seed := bip39.NewSeed(mnemonic, "Secret Passphrase")

	masterKey, _ := bip32.NewMasterKey(seed)
	publicKey := masterKey.PublicKey()
	fmt.Println(publicKey)
}

////测试助记词有效
//func DeriveAddressFromMnemonic() {
//	nm := "transfer between penalty abandon expire space cube strong dog session expose net"
//	//助记词转化为种子 -->账户地址
//	//先推导路径 再获得钱包
//	//MustParseDerivationPath("m/44'/60'/0'/0/0")
//	path, err := accounts.ParseDerivationPath("m/44'/60'/0'/0/1")
//	if err != nil {
//
//	}
//	seed, err := bip39.NewSeedWithErrorChecking(nm, "")
//	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
//	if err != nil {
//	}
//	privateKey, err := derivePrivateKey(path, masterKey)
//	publicKey, err := derivePublicKey(privateKey)
//	address := crypto.PubkeyToAddress(*publicKey)
//	fmt.Println(address)
//}
