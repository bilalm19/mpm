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

func Login() error {
	creds, err := enterCredentials(false)
	if err != nil {
		return err
	}
	mashalledCreds, err := json.Marshal(creds)
	if err != nil {
		return err
	}

	reader := strings.NewReader(string(mashalledCreds))

	req, err := http.NewRequest("POST", "http://localhost:2000/login", reader)
	if err != nil {
		return err
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
	logger.Info(string(body))

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
	logger.Info(string(body))
	return nil
}
