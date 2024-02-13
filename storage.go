package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type Storage interface {
	CreateAccount(*Account) error
	DeleteAccount(int) error
	UpdateAccount(*Account) error
	GetAccounts() ([]*Account, error)
	GetAccountID(int) (*Account, error)
}

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore() (*PostgresStore, error) {
	connStr := "user=postgres dbname=postgres password=gobank sslmode=disable"
	db, err := sql.Open("postgres", connStr)
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
		id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
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
	password, err := s.bcryptPW(acc.Password)
	if err != nil {
		return err
	}
	resp, err := s.db.Query(query,
		acc.AccountName,
		password,
		acc.Username,
		acc.PermissionID,
		acc.PhoneNumber,
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
func (s *PostgresStore) UpdateAccount(*Account) error {
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
	return account, err
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

func (s *PostgresStore) compareHashAndPW(id int, userPassword []byte) error {

	hashAndPw, err := s.getAccountPW(id)
	if err != nil {
		return fmt.Errorf("given id not found")
	}

	if err := bcrypt.CompareHashAndPassword(hashAndPw, userPassword); err != nil {
		return fmt.Errorf("password verification failed: %w", err)
	}
	return nil

}

func (s *PostgresStore) bcryptPW(password string) ([]byte, error) {

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("Failed to hash password: %w", err)
	}
	return hashPassword, err
}
