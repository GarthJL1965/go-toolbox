package crypto

import (
	"fmt"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	pmailcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	tbcrypto "go.imperva.dev/toolbox/crypto"
	"go.imperva.dev/zerolog/log"
)

// PGPKeyPair represents a PGP key pair for use with Vault.
type PGPKeyPair struct {
	armoredKey string
	passphrase string
	privateKey *pmailcrypto.Key
}

// NewPGPKeyPair returns a new PGP key pair for use with Vault.
//
// Be sure to call ClearPrivateParams on the returned key to clear memory out when finished with the object.
func NewPGPKeyPair(name, email, keyType string, bits int) (*PGPKeyPair, error) {
	restoreLogger, _ := log.ReplaceGlobal(log.With().PackageCaller().Logger())
	defer restoreLogger()
	kp := &PGPKeyPair{}

	// generate a new key
	key, err := pmailcrypto.GenerateKey(name, email, keyType, bits)
	if err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("Failed to generate private key: %s", err.Error())
		return nil, err
	}
	kp.privateKey = key

	// encrypt the key with a random password
	kp.passphrase = tbcrypto.GeneratePassword(32, 5, 5, 5)
	locked, err := key.Lock([]byte(kp.passphrase))
	if err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("Failed to lock private key: %s", err.Error())
		return nil, err
	}
	armoredKey, err := locked.Armor()
	if err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("Failed to armor private key: %s", err.Error())
		return nil, err
	}
	kp.armoredKey = armoredKey
	return kp, nil
}

// NewPGPKeyPairFromArmor returns a new PGP key pair for use with Vault from the given armored private key.
//
// Be sure to call ClearPrivateParams on the returned key to clear memory out when finished with the object.
func NewPGPKeyPairFromArmor(armoredKey, passphrase string) (*PGPKeyPair, error) {
	restoreLogger, _ := log.ReplaceGlobal(log.With().PackageCaller().Logger())
	defer restoreLogger()
	kp := &PGPKeyPair{
		armoredKey: armoredKey,
		passphrase: passphrase,
	}

	// load the key
	key, err := crypto.NewKeyFromArmored(kp.armoredKey)
	if err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("Failed to load private key from PGP armor: %s", err.Error())
		return nil, err
	}

	// check to see if the key is locked
	locked, err := key.IsLocked()
	if err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("Unable to determine if private key is locked: %s", err.Error())
		return nil, err
	}
	if !locked {
		kp.privateKey = key
		return kp, nil
	}

	// unlock the key
	unlocked, err := key.Unlock([]byte(kp.passphrase))
	if err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("Failed to unlock private key: %s", err.Error())
		return nil, err
	}
	kp.privateKey = unlocked
	return kp, nil
}

// ClearPrivateParams clears out memory attached to the private key.
func (kp *PGPKeyPair) ClearPrivateParams() {
	if kp.privateKey != nil {
		kp.privateKey.ClearPrivateParams()
	}
}

// ArmoredPrivateKey returns the private key wrapped in PGP armor.
func (kp *PGPKeyPair) GetArmoredPrivateKey() (string, error) {
	restoreLogger, _ := log.ReplaceGlobal(log.With().PackageCaller().Logger())
	defer restoreLogger()

	if kp.armoredKey == "" {
		err := fmt.Errorf("private key has not been initialized")
		log.
			Error().Stack().
			Err(err).
			Msgf("Failed to get armored private key: %s", err.Error())
		return "", err
	}
	return kp.armoredKey, nil
}

// ArmoredPublicKey returns the public key wrapped in PGP armor.
func (kp *PGPKeyPair) GetArmoredPublicKey() (string, error) {
	restoreLogger, _ := log.ReplaceGlobal(log.With().PackageCaller().Logger())
	defer restoreLogger()

	if kp.privateKey == nil { // should never happen
		err := fmt.Errorf("private key has not been initialized")
		log.
			Error().Stack().
			Err(err).
			Msgf("Failed to get armored public key: %s", err.Error())
		return "", err
	}
	return kp.privateKey.GetArmoredPublicKey()
}
