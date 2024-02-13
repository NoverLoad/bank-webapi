package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

type APIServer struct {
	listenAddr string
	store      Storage
}

func NewAPIServer(listenAddr string, store Storage) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,
		store:      store,
	}
}

func (s *APIServer) RUN() {

	r := mux.NewRouter()

	//Testing
	r.HandleFunc("/authpassword/{accountName}", makeHTTPHandleFunc(s.handleGetAccountPW))

	r.HandleFunc("/account", makeHTTPHandleFunc(s.handleAccount))
	r.HandleFunc("/account/{id}", makeHTTPHandleFunc(s.handleGetAccountByID))
	log.Println("JSON API server running port ", s.listenAddr)
	http.ListenAndServe(s.listenAddr, r)
}

func (s *APIServer) handleAccount(w http.ResponseWriter, r *http.Request) error {
	if r.Method == "GET" {
		return s.handleGetAccount(w, r)
	}
	if r.Method == "POST" {
		return s.handleCreateAccount(w, r)
	}

	if r.Method == "POST" {
		return s.handleTransfer(w, r)
	}

	return fmt.Errorf("method not allowed %s", r.Method)
}
func (s *APIServer) handleGetAccount(w http.ResponseWriter, r *http.Request) error {
	accounts, err := s.store.GetAccounts()
	if err != nil {
		return err
	}
	return WriteJson(w, http.StatusOK, accounts)

}
func (s *APIServer) handleGetAccountByID(w http.ResponseWriter, r *http.Request) error {
	if r.Method == "GET" {
		id, err := getID(r)
		if err != nil {
			return err
		}
		account, err := s.store.GetAccountID(id)
		if err != nil {
			return err
		}

		return WriteJson(w, http.StatusOK, account)
	}
	if r.Method == "DELETE" {
		return s.handleDeleteAccount(w, r)
	}

	return fmt.Errorf("method not allowed %s", r.Method)
}

func (s *APIServer) handleCreateAccount(w http.ResponseWriter, r *http.Request) error {
	createAccountRes := new(Account)
	if err := json.NewDecoder(r.Body).Decode(&createAccountRes); err != nil {
		return err
	}
	account := NewAccount(
		createAccountRes.AccountName,
		createAccountRes.Password,
		createAccountRes.Username,
		createAccountRes.PermissionID,
		createAccountRes.PhoneNumber,
		createAccountRes.Status)
	if err := s.store.CreateAccount(account); err != nil {
		return err
	}

	return WriteJson(w, http.StatusOK, &account)
}
func (s *APIServer) handleDeleteAccount(w http.ResponseWriter, r *http.Request) error {
	id, err := getID(r)
	if err != nil {
		return err
	}
	if err := s.store.DeleteAccount(id); err != nil {
		return err
	}

	return WriteJson(w, http.StatusOK, map[string]int{"delete": id})

}

func (s *APIServer) handleTransfer(w http.ResponseWriter, r *http.Request) error {
	return nil
}

type apiFunc func(http.ResponseWriter, *http.Request) error
type ApiError struct {
	Error string `json:"error"`
}
type ApiSuccess struct {
	Success string `json:"success"`
}

func WriteJson(w http.ResponseWriter, status int, v any) error {

	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(status)

	return json.NewEncoder(w).Encode(v)
}

func makeHTTPHandleFunc(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			WriteJson(w, http.StatusBadRequest, ApiError{Error: err.Error()})
		}
	}
}

func getID(r *http.Request) (int, error) {
	idStr := mux.Vars(r)["id"]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return id, fmt.Errorf("invalid id given %s", idStr)
	}
	return id, nil

}

// Testing
func (s *APIServer) handleGetAccountPW(w http.ResponseWriter, r *http.Request) error {

	resStr := mux.Vars(r)["accountName"]

	exists, err := s.store.CheckAccountNameExists(resStr)
	if err != nil {
		return err
	}
	if exists {

		fmt.Println(exists, "账号已经存在")
		return nil
	}
	fmt.Println(exists, "可以创建账号")
	return WriteJson(w, http.StatusOK, ApiSuccess{Success: "accountName not found"})
	// idStr := mux.Vars(r)["id"]
	// id, _ := strconv.Atoi(idStr)
	// fmt.Println(id)
	// pw, err := s.store.GetAccountPhone(id)
	// if err != nil {
	// 	return err
	// }
	// decryptPhone, err := DecryptPhoneNumber(string(pw))
	// if err != nil {
	// 	return err
	// }

	// fmt.Println(pw)
	// return WriteJson(w, http.StatusOK, decryptPhone)

}
