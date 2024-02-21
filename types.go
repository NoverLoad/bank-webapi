package main

import (
	"time"
)

type AccountPW struct {
	Password  string    `json:"password"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func NewAccountPW(Password string) *AccountPW {
	return &AccountPW{
		Password:  Password,
		UpdatedAt: time.Now(),
	}
}

type Account struct {
	ID           int       `json:"id"`
	AccountName  string    `json:"accountName"`
	Password     string    `json:"-"`
	Username     string    `json:"username"`
	PermissionID int       `json:"permissionID"`
	PhoneNumber  string    `json:"phoneNumber"`
	Status       string    `json:"status"`
	GroupID      int       `json:"groupid"`
	CreatedAt    time.Time `json:"-"`
	UpdatedAt    time.Time `json:"-"`
}

type Group struct {
	ID        int        `json:"id" gorm:"primaryKey;autoIncrement"`
	CreatedAt time.Time  `json:"-"`
	UpdatedAt time.Time  `json:"-"`
	DeletedAt *time.Time `json:"-"`
	Name      string     `json:"name"`
	OrgID     int        `json:"-"`
	ParentID  int        `json:"parent_id"`
	UserIDs   []string   `json:"-" gorm:"type:text[]"`
}

type AccountGroup struct {
	Account     Account
	Group       Group
	UserIDsJson []byte `json:"-"`
}

// GroupID int
func NewAccount(AccountName, Password, Username string, PermissionID int, PhoneNumber, Status string, GroupID int) *Account {
	return &Account{
		AccountName:  AccountName,
		Password:     Password,
		Username:     Username,
		PermissionID: PermissionID,
		PhoneNumber:  PhoneNumber,
		Status:       Status,
		GroupID:      GroupID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}

func NewAccountGroup(AccountName, Password, Username string, PermissionID int, PhoneNumber, Status string, GroupID int) *AccountGroup {

	account := Account{
		AccountName:  AccountName,
		Password:     Password,
		Username:     Username,
		PermissionID: PermissionID,
		PhoneNumber:  PhoneNumber,
		Status:       Status,
		GroupID:      GroupID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	return &AccountGroup{
		Account: account,
	}
}
