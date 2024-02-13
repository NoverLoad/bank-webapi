package main

import (
	"time"
)

type Account struct {
	ID           int       `json:"id"`
	AccountName  string    `json:"accountName"`
	Password     string    `json:"password"`
	Username     string    `json:"username"`
	PermissionID int       `json:"permissionID"`
	PhoneNumber  string    `json:"phoneNumber"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

func NewAccount(AccountName, Password, Username string, PermissionID int, PhoneNumber, Status string) *Account {
	return &Account{
		AccountName:  AccountName,
		Password:     Password,
		Username:     Username,
		PermissionID: PermissionID,
		PhoneNumber:  PhoneNumber,
		Status:       Status,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}
