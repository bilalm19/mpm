package client

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"mpm/logger"
	"mpm/server"
	"net/http"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

type ReqType uint8

const (
	post ReqType = iota
	get
	del
)

func Login(rt uint8) error {
	creds, err := enterCredentials(false)
	if err != nil {
		return err
	}

	var req *http.Request
	if ReqType(rt) == post {
		req, err = postSecrets(creds)
		if err != nil {
			return err
		}
	} else if ReqType(rt) == get {
		req, err = getSecrets(creds)
		if err != nil {
			return err
		}
	} else if ReqType(rt) == del {
		req, err = delAccount(creds)
		if err != nil {
			return err
		}
	} else {
		return errors.New("unknown request type")
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusOK {
		logger.Info("Server responded with " + string(body))
	} else {
		logger.Error("Server responded with " + string(body))
	}

	return nil
}

func SignUp() error {
	creds, err := enterCredentials(true)
	if err != nil {
		return err
	}
	mashalledCreds, err := json.Marshal(creds)
	if err != nil {
		return err
	}
	resp, err := http.Post("http://localhost:2000/signup", "application/json", bytes.NewBuffer(mashalledCreds))
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusOK {
		logger.Info("Server responded with " + string(body))
	} else {
		logger.Error("Server responded with " + string(body))
	}
	return nil
}

func enterCredentials(signup bool) (server.Credentials, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter username: ")
	username, err := reader.ReadString('\n')
	username = strings.Replace(username, "\n", "", -1)

	if err != nil {
		return server.Credentials{}, err
	}

	fmt.Print("Enter password: ")
	masterPassword, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Print("\n")
	if err != nil {
		return server.Credentials{}, err
	}

	if signup {
		fmt.Print("Confirm password: ")
		retryPassword, err := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Print("\n")
		if err != nil {
			logger.Fatal(err)
		}

		if string(retryPassword) != string(masterPassword) {
			return server.Credentials{}, errors.New("entered passwords did not match")
		}
	}

	return server.Credentials{
		Username: username,
		Password: string(masterPassword),
	}, nil

}

func postSecrets(creds server.Credentials) (*http.Request, error) {
	secrets := make(map[string]string)
	secrets["service1"] = "hunter2"
	secrets["service2"] = "hunter3"
	creds.SecretList = secrets

	mashalledCreds, err := json.Marshal(creds)
	if err != nil {
		return &http.Request{}, err
	}

	reader := strings.NewReader(string(mashalledCreds))

	req, err := http.NewRequest("POST", "http://localhost:2000/login", reader)
	if err != nil {
		return &http.Request{}, err
	}

	return req, nil
}

func getSecrets(creds server.Credentials) (*http.Request, error) {
	mashalledCreds, err := json.Marshal(creds)
	if err != nil {
		return &http.Request{}, err
	}

	reader := strings.NewReader(string(mashalledCreds))

	req, err := http.NewRequest("GET", "http://localhost:2000/login", reader)
	if err != nil {
		return &http.Request{}, err
	}

	return req, nil
}

func delAccount(creds server.Credentials) (*http.Request, error) {
	mashalledCreds, err := json.Marshal(creds)
	if err != nil {
		return &http.Request{}, err
	}

	reader := strings.NewReader(string(mashalledCreds))

	req, err := http.NewRequest("DELETE", "http://localhost:2000/login", reader)
	if err != nil {
		return &http.Request{}, err
	}

	return req, nil
}
