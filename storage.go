package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type Storage interface {
	CreateAccount(*Account) error
	DeleteAccount(int) error
	UpdateAccount(int,*Account) error
	GetAccounts() ([]*Account, error)
	GetAccountID(int) (*Account, error)
	GetAccountPhone(int) (string, error)
	CheckAccountNameExists(string) (bool, error)
	CompareHashAndPW(int, []byte) error
}

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore() (*PostgresStore, error) {
	connStr := "user=postgres dbname=postgres password=gobank sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	//defer db.Close()
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return &PostgresStore{
		db: db,
	}, nil
}

func (s *PostgresStore) Init() error {
	return s.createAccountTable()
}

func (s *PostgresStore) createAccountTable() error {
	query := `CREATE TABLE  if not exists users(
		user_id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
		accountname VARCHAR(100),
		password BYTEA NOT NULL,
		username VARCHAR(50),
		permission_id INT,
		phone_number VARCHAR(100),
		status VARCHAR(10), 
		created_at TIMESTAMP,
		updated_at TIMESTAMP
	  );`
	_, err := s.db.Exec(query)
	return err
}

func (s *PostgresStore) CreateAccount(acc *Account) error {
	query := `insert into users 
	(accountname,
		password,
		username,
		permission_id,
		phone_number,
		status,
		created_at,
		updated_at)
	values
	($1,$2,$3,$4,$5,$6,$7,$8)
	`
	password, err := bcryptPW(acc.Password)
	if err != nil {
		return err
	}
	phoneNumber, err := EncryptPhoneNumber(acc.PhoneNumber)
	if err != nil {
		return err
	}
	resp, err := s.db.Query(query,
		acc.AccountName,
		password,
		acc.Username,
		acc.PermissionID,
		phoneNumber,
		acc.Status,
		acc.CreatedAt,
		acc.UpdatedAt,
	)
	if err != nil {
		return err
	}
	fmt.Printf("%+v\n", resp)
	return nil

}
func (s *PostgresStore) DeleteAccount(id int) error {
	_, err := s.db.Query("delete from users where user_id = $1", id)
	return err
}

func (s *PostgresStore) UpdateAccount(id int,acc *Account) error {

	if acc.Password != "" {
		password, err := bcryptPW(acc.Password)
		if err != nil {
			return err
		}
		acc.Password = string(password)
	}

	if acc.PhoneNumber != "" {
		encryptedPhone, err := EncryptPhoneNumber(acc.PhoneNumber)
		if err != nil {
			return err
		}
		acc.PhoneNumber = encryptedPhone
	}

	query := `UPDATE users  
              SET accountname = $1,  
                  password = $2,  
                  username = $3,  
                  permission_id = $4,  
                  phone_number = $5,  
                  status = $6,  
                  updated_at = $7  
              WHERE user_id = $8`

	_, err := s.db.Exec(query,
		acc.AccountName,
		acc.Password,
		acc.Username,
		acc.PermissionID,
		acc.PhoneNumber,
		acc.Status,
		time.Now(),
		id,
	)
	fmt.Println(id)
	if err != nil {
		return err
	}

	return nil
}
func (s *PostgresStore) GetAccountID(id int) (*Account, error) {
	rows, err := s.db.Query("select * from users where user_id = $1", id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		return scanIntoAccount(rows)
	}
	return nil, fmt.Errorf("account id %d is not found ", id)
}

func (s *PostgresStore) GetAccounts() ([]*Account, error) {
	rows, err := s.db.Query("select * from users")
	if err != nil {
		return nil, err
	}
	accounts := []*Account{}
	for rows.Next() {
		account, err := scanIntoAccount(rows)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func scanIntoAccount(rows *sql.Rows) (*Account, error) {
	account := new(Account)
	err := rows.Scan(
		&account.ID,
		&account.AccountName,
		&account.Password,
		&account.Username,
		&account.PermissionID,
		&account.PhoneNumber,
		&account.Status,
		&account.CreatedAt,
		&account.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	decryptPhone, err := DecryptPhoneNumber(account.PhoneNumber)
	if err != nil {
		return nil, err
	}
	account.PhoneNumber = decryptPhone
	return account, nil
}

func (s *PostgresStore) getAccountPW(id int) ([]byte, error) {

	var password string

	err := s.db.QueryRow("select password from users where user_id = $1", id).Scan(&password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("given ID not found")
		}
		return nil, err
	}
	return []byte(password), nil
}

func (s *PostgresStore) CompareHashAndPW(id int, userPassword []byte) error {

	hashAndPw, err := s.getAccountPW(id)
	if err != nil {
		return fmt.Errorf("given id not found")
	}

	if err := bcrypt.CompareHashAndPassword(hashAndPw, userPassword); err != nil {
		return fmt.Errorf("password verification failed: %w", err)
	}
	return nil

}

func bcryptPW(password string) ([]byte, error) {

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("Failed to hash password: %w", err)
	}
	return hashPassword, err
}

// 生产环境应该将decryptPhoneKey 存入到环境变量中
const decryptPhoneKey = "f3125f744df88a6b53bb3c4f18f5debc"

func EncryptPhoneNumber(phoneNumber string) (string, error) {
	key := []byte(decryptPhoneKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	padding := block.BlockSize() - len(phoneNumber)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	phoneNumber = phoneNumber + string(padtext)

	ciphertext := make([]byte, aes.BlockSize+len(phoneNumber))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], []byte(phoneNumber))

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptPhoneNumber(cipherText string) (string, error) {
	key := []byte(decryptPhoneKey)
	ciphertext, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	padding := int(ciphertext[len(ciphertext)-1])
	if padding < 1 || padding > aes.BlockSize {
		return "", fmt.Errorf("invalid padding")
	}

	return string(ciphertext[:len(ciphertext)-padding]), nil
}

// Testing
func (s *PostgresStore) GetAccountPhone(id int) (string, error) {

	var phone string

	err := s.db.QueryRow("select phone_number from users where user_id = $1", id).Scan(&phone)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("given ID not found")
		}
		return "", err
	}
	return phone, nil
}

func (s *PostgresStore) CheckAccountNameExists(accountName string) (bool, error) {

	query := `SELECT EXISTS(SELECT 1 FROM users WHERE accountname = $1)`
	var exists bool
	err := s.db.QueryRow(query, accountName).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}
