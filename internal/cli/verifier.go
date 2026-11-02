package cli

import (
	"errors"
	"fmt"

	"github.com/ndreuu/go-gophkeeper/internal/cryptoutil"
	"github.com/ndreuu/go-gophkeeper/internal/model"
)

const verifierText = "GophKeeper vault key verifier v1"

func (r *runner) visibleCount() int {
	count := 0
	for _, record := range r.state.Records {
		if record.ID != model.MasterVerifierID {
			count++
		}
	}
	return count
}

func (r *runner) cachedVerifier() (model.Record, bool) {
	for _, record := range r.state.Records {
		if record.ID == model.MasterVerifierID {
			return record, true
		}
	}
	return model.Record{}, false
}

func checkVerifier(key []byte, record model.Record) error {
	secret, err := cryptoutil.Decrypt(key, model.MasterVerifierID, record.Ciphertext)
	if err != nil || secret.Kind != model.KindText || secret.Text == nil || *secret.Text != verifierText {
		return errors.New("cannot unlock vault; check the master password and encrypted verifier")
	}
	return nil
}

func (r *runner) ensureVerifier(key []byte) error {
	record, err := r.api.Get(r.ctx, model.MasterVerifierID)
	if err == nil {
		return checkVerifier(key, record)
	}
	if !errors.Is(err, model.ErrNotFound) {
		return fmt.Errorf("read vault key verifier: %w", err)
	}
	for _, existing := range r.state.Records {
		if existing.ID == model.MasterVerifierID {
			continue
		}
		if _, err := cryptoutil.Decrypt(key, existing.ID, existing.Ciphertext); err != nil {
			return errors.New("cannot decrypt vault; check the master password before adding data")
		}
		break
	}
	text := verifierText
	ciphertext, err := cryptoutil.Encrypt(key, model.MasterVerifierID, model.Secret{Kind: model.KindText, Title: "Vault key verifier", Text: &text})
	if err != nil {
		return err
	}
	_, err = r.api.Put(r.ctx, model.MasterVerifierID, model.PutRequest{Ciphertext: ciphertext})
	if errors.Is(err, model.ErrConflict) {
		winner, getErr := r.api.Get(r.ctx, model.MasterVerifierID)
		if getErr != nil {
			return fmt.Errorf("read concurrently initialized vault verifier: %w", getErr)
		}
		return checkVerifier(key, winner)
	}
	if err != nil {
		return fmt.Errorf("initialize vault key verifier: %w", err)
	}
	return r.sync()
}
