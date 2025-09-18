package model

import (
	"time"
)

// User user table
type User struct {
	ID        uint64     `json:"id" gorm:"primaryKey;autoIncrement:false"` // Snowflake algorithm generated ID
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
	DeletedAt *time.Time `json:"deletedAt,omitempty" gorm:"index"`
}

// UserEthWallet user Ethereum wallet table
type UserEthWallet struct {
	UserID  uint64 `json:"user_id" gorm:"primaryKey"`
	Address string `json:"address" gorm:"primaryKey;size:42"` // Ethereum address, 42 characters
}

// TableName specifies table name
func (UserEthWallet) TableName() string {
	return "user_eth_wallets"
}

type UserListRequest struct {
	PaginationRequest
}

type UserListResponse struct {
	Data       []*User                 `json:"data"`
	Pagination *PaginationResponse     `json:"pagination"`
}