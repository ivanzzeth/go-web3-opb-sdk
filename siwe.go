package web3opb

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ivanzzeth/go-web3-opb-sdk/model"
	"github.com/spruceid/siwe-go"
)

func (c *Client) SiweGetNonce() (string, error) {
	url := fmt.Sprintf("%s/api/%s/siwe/nonce", c.baseURL, c.version)
	resp, err := c.httpClient.Post(url, "application/json", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var nonceResp model.APIResponse[model.SiweNonceResponse]
	err = json.NewDecoder(resp.Body).Decode(&nonceResp)
	if err != nil {
		return "", err
	}

	if nonceResp.ApiError.HasError() {
		return "", nonceResp.ApiError
	}

	return nonceResp.Data.Nonce, nil
}

func (c *Client) SiweSignMessage(message *siwe.Message) (*model.SiweVerifyRequest, error) {
	messageStr := message.String()

	data := []byte(messageStr)
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	messageHash := crypto.Keccak256Hash([]byte(msg))
	signature, err := crypto.Sign(messageHash.Bytes(), c.ethPrivateKey)
	if err != nil {
		return nil, err
	}

	signature[64] += 27

	return &model.SiweVerifyRequest{
		Message:   messageStr,
		Signature: "0x" + hex.EncodeToString(signature),
	}, nil
}

func (c *Client) SiweVerify(message *model.SiweVerifyRequest) (model.SiweVerifyResponse, error) {
	url := fmt.Sprintf("%s/api/%s/siwe/verify", c.baseURL, c.version)
	messageJSON, err := json.Marshal(message)
	if err != nil {
		return model.SiweVerifyResponse{}, err
	}
	resp, err := c.httpClient.Post(url, "application/json", bytes.NewBuffer(messageJSON))
	if err != nil {
		return model.SiweVerifyResponse{}, err
	}
	defer resp.Body.Close()

	var authResultResp model.APIResponse[model.SiweVerifyResponse]
	err = json.NewDecoder(resp.Body).Decode(&authResultResp)
	if err != nil {
		return model.SiweVerifyResponse{}, err
	}

	if authResultResp.ApiError.HasError() {
		return model.SiweVerifyResponse{}, authResultResp.ApiError
	}

	return authResultResp.Data, nil
}

func GenerateEthPrivateKey() (*ecdsa.PrivateKey, common.Address, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, common.Address{}, err
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	return privateKey, address, nil
}
