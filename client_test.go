package web3opb

import (
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/ivanzzeth/go-web3-opb-sdk/model"
	"github.com/spruceid/siwe-go"
	"github.com/stretchr/testify/assert"
)

func TestNewApiClient(t *testing.T) {
	baseURL := "http://localhost:8700"
	privateKey, address, err := GenerateEthPrivateKey()
	assert.NoError(t, err)
	assert.NotNil(t, privateKey)
	assert.NotNil(t, address)

	privateKeyHex := hex.EncodeToString(privateKey.D.Bytes())

	apiClient, err := NewApiClient(baseURL, "localhost", "v1", privateKeyHex)
	assert.NoError(t, err)
	assert.NotNil(t, apiClient)

	nonce, err := apiClient.SiweGetNonce()
	assert.NoError(t, err)
	assert.NotEmpty(t, nonce)

	// Test SiweMessage
	siweMessage, err := siwe.InitMessage("localhost", address.Hex(), baseURL, nonce, nil)
	assert.NoError(t, err)
	assert.NotNil(t, siweMessage)

	siweMessageModel, err := apiClient.SiweSignMessage(siweMessage)
	assert.NoError(t, err)
	assert.NotNil(t, siweMessageModel)

	siweAuthResult, err := apiClient.SiweVerify(siweMessageModel)
	assert.NoError(t, err)
	assert.NotNil(t, siweAuthResult)

	jwtResult, err := apiClient.JwtVerify(&model.JwtVerifyRequest{Token: siweAuthResult.Token})
	assert.NoError(t, err)
	assert.NotNil(t, jwtResult)
	assert.True(t, jwtResult.Valid)
	assert.Equal(t, address.Hex(), jwtResult.Payload["ethAddress"])
	assert.Equal(t, "localhost", jwtResult.Payload["domain"])
	assert.Equal(t, strconv.FormatUint(siweAuthResult.User.UserID, 10), jwtResult.Payload["userId"])

	jwtResult, err = apiClient.JwtVerifyLocally(&model.JwtVerifyRequest{Token: siweAuthResult.Token})
	assert.NoError(t, err)
	assert.NotNil(t, jwtResult)
	assert.True(t, jwtResult.Valid)
	assert.Equal(t, address.Hex(), jwtResult.Payload["ethAddress"])
	assert.Equal(t, "localhost", jwtResult.Payload["domain"])
	assert.Equal(t, strconv.FormatUint(siweAuthResult.User.UserID, 10), jwtResult.Payload["userId"])

	user, err := apiClient.UserGetByID(siweAuthResult.User.UserID)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, siweAuthResult.User.UserID, user.ID)

	// Test normal users can't get other users' information
	user, err = apiClient.UserGetByEthWallet(address.Hex())
	assert.Error(t, err)
	assert.Nil(t, user)
}
