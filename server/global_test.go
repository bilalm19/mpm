package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type DuplicateUser struct {
	Err error
}

type MissedAccountCreation struct {
	Err error
}

func (e *DuplicateUser) Error() string {
	return e.Err.Error()
}

func NewDuplicateUser(err error) error {
	return &DuplicateUser{err}
}

func (e *MissedAccountCreation) Error() string {
	return e.Err.Error()
}

func NewMissedAccountCreation(err error) error {
	return &MissedAccountCreation{err}
}

func TestMPM(t *testing.T) {
	var pass [10]chan bool
	var users [10]credentials
	userMap := make(map[string]string)

	users[0].Username = "john"
	users[0].Password = "123"

	users[1].Username = "john"
	users[1].Password = "1234"

	users[2].Username = "jane"
	users[2].Password = "123"

	users[3].Username = "jane"
	users[3].Password = "1235"

	users[4].Username = "john"
	users[4].Password = "123"

	users[5].Username = "bob"
	users[5].Password = "123"

	users[6].Username = "set"
	users[6].Password = "123"

	users[7].Username = "bat"
	users[7].Password = "123"

	users[8].Username = "nat"
	users[8].Password = "123"

	users[9].Username = "lat"
	users[9].Password = "123"

	for i := range pass {
		userMap[users[i].Username] = users[i].Password
		pass[i] = make(chan bool)
		go requestAccountCreation(users[i].Username, users[i].Password, pass[i])

	}
	for i := range pass {

		if !<-pass[i] {
			t.Errorf("Request number %d failed", i)
		}
	}

	err := checkDatabase(len(userMap))
	if err != nil {
		switch err.(type) {
		case *DuplicateUser:
			t.Error(err)
		default:
			t.Fatal(err)
		}
	}
}

func requestAccountCreation(user string, password string, pass chan bool) {
	creds := credentials{
		Username: user,
		Password: password,
	}
	marshalledCreds, err := json.Marshal(creds)
	if err != nil {
		log.Println(err)
		pass <- false
	}
	reqBody := strings.NewReader(string(marshalledCreds))
	request, err := http.NewRequest(http.MethodPost, "/", reqBody)
	if err != nil {
		log.Println(err)
		pass <- false
	}
	response := httptest.NewRecorder()

	registerNewUser(response, request)
	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		pass <- false
	}

	if string(respBody) != "Account created" && response.Code != http.StatusOK {
		if string(respBody) != "Username is already in use" && response.Code != http.StatusBadRequest {
			log.Printf("StatusCode: %d; Response: %s\n", response.Code, respBody)
			pass <- false
		}
	}

	pass <- true
}

func checkDatabase(uniqueUserCount int) error {
	file, err := os.Open("db/users")
	if err != nil {
		return err
	}
	defer file.Close()

	users := make(map[string]string)
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadBytes(10)
		if err != nil && err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		var creds credentialStorageStructure
		json.Unmarshal(line, &creds)

		if _, ok := users[creds.Username]; ok {
			log.Printf("%s found more than once.\n", creds.Username)
			return NewDuplicateUser(errors.New("mishandled duplication"))
		}
		users[creds.Username] = string(creds.Password)
	}

	if uniqueUserCount != len(users) {
		return NewMissedAccountCreation(errors.New(
			"the number of accounts created are less than the unique requests"))
	}

	return nil
}
