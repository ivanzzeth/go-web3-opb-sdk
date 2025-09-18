package model

import (
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"gorm.io/gorm"
)

type TimeModel struct {
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `json:"deletedAt" gorm:"index"`
}

func ComposeID(keys ...string) string {
	// return strings.Join(keys, "-")
	ID := strings.Join(keys, "-")
	return crypto.Keccak256Hash([]byte(ID)).Hex()
}
