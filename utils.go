package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
)

func writeKeyFile(file string, content []byte) error {
	// Create the keystore directory with appropriate permissions
	// in case it is not present yet.
	const dirperm = 0700
	err := os.MkdirAll(filepath.Dir(file), dirperm)
	if err != nil {
		return err
	}
	tempFile, err := ioutil.TempFile(filepath.Dir(file), "."+filepath.Base(file)+".tmp")
	if err != nil {
		return err
	}
	_, err = tempFile.Write(content)
	if err != nil {
		tempFile.Close()
		os.Remove(tempFile.Name())
		return err
	}
	tempFile.Close()
	return os.Rename(tempFile.Name(), file)
}
