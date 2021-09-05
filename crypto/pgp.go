package crypto

import (
	"context"
	"errors"

	pmailcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	"go.imperva.dev/zerolog"
	"go.imperva.dev/zerolog/log"
)

// PGPKeyPair represents a PGP key pair.
type PGPKeyPair struct {
	armoredKey string
	passphrase string
	privateKey *pmailcrypto.Key
}

// NewPGPKeyPair returns a new PGP key pair.
//
// Be sure to call ClearPrivateParams on the returned key to clear memory out when finished with the object.
//
// The following errors are returned by this function:
// ErrGeneratePGPKeyFailure, ErrLockPGPKeyFailure, ErrPGPArmorKeyFailure
func NewPGPKeyPair(name, email, keyType string, bits int, ctx context.Context) (*PGPKeyPair, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}
	logger = logger.With().Str("name", name).Str("email", email).Str("key_type", keyType).Int("bits", bits).Logger()
	kp := &PGPKeyPair{}

	// generate a new key
	key, err := pmailcrypto.GenerateKey(name, email, keyType, bits)
	if err != nil {
		e := &ErrGeneratePGPKeyFailure{Err: err, Name: name, Email: email, KeyType: keyType, Bits: bits}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	kp.privateKey = key

	// encrypt the key with a random password
	kp.passphrase = GeneratePassword(32, 5, 5, 5)
	locked, err := key.Lock([]byte(kp.passphrase))
	if err != nil {
		e := &ErrLockPGPKeyFailure{Err: err, Name: name, Email: email, KeyType: keyType, Bits: bits}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	armoredKey, err := locked.Armor()
	if err != nil {
		e := &ErrArmorPGPKeyFailure{Err: err, Name: name, Email: email, KeyType: keyType, Bits: bits}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	kp.armoredKey = armoredKey
	return kp, nil
}

// NewPGPKeyPairFromArmor returns a new PGP key pair from the given armored private key.
//
// Be sure to call ClearPrivateParams on the returned key to clear memory out when finished with the object.
//
// The following errors are returned by this function:
// ErrLoadPGPKeyFailure, ErrUnlockPGPKeyFailure
func NewPGPKeyPairFromArmor(armoredKey, passphrase string, ctx context.Context) (*PGPKeyPair, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}
	kp := &PGPKeyPair{
		armoredKey: armoredKey,
		passphrase: passphrase,
	}

	// load the key
	key, err := pmailcrypto.NewKeyFromArmored(kp.armoredKey)
	if err != nil {
		e := &ErrLoadPGPKeyFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}

	// check to see if the key is locked
	locked, err := key.IsLocked()
	if err != nil {
		e := &ErrUnlockPGPKeyFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	if !locked {
		kp.privateKey = key
		return kp, nil
	}

	// unlock the key
	unlocked, err := key.Unlock([]byte(kp.passphrase))
	if err != nil {
		e := &ErrUnlockPGPKeyFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
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
//
// The following errors are returned by this function:
// ErrGetPGPKeyFailure
func (kp *PGPKeyPair) GetArmoredPrivateKey(ctx context.Context) (string, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	if kp.armoredKey == "" {
		e := &ErrGetPGPKeyFailure{Err: errors.New("private key has not been initialized")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return "", e
	}
	return kp.armoredKey, nil
}

// ArmoredPublicKey returns the public key wrapped in PGP armor.
//
// The following errors are returned by this function:
// ErrGetPGPKeyFailure
func (kp *PGPKeyPair) GetArmoredPublicKey(ctx context.Context) (string, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	if kp.privateKey == nil { // should never happen
		e := &ErrGetPGPKeyFailure{Err: errors.New("private key has not been initialized")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return "", e
	}
	key, err := kp.privateKey.GetArmoredPublicKey()
	if err != nil {
		e := &ErrGetPGPKeyFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return "", e
	}
	return key, nil
}
