package passwd

import (
	"github.com/infodancer/auth"
	"github.com/infodancer/auth/errors"
)

func init() {
	auth.RegisterAuthAgent("passwd", func(config auth.AuthAgentConfig) (auth.AuthenticationAgent, error) {
		if config.CredentialBackend == "" {
			return nil, errors.ErrAuthAgentConfigInvalid
		}
		// KeyBackend defaults to same directory as credential file
		keyDir := config.KeyBackend
		if keyDir == "" {
			return nil, errors.ErrAuthAgentConfigInvalid
		}
		return NewAgent(config.CredentialBackend, keyDir)
	})
}
