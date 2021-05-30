package server

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"mpm/logging"
	"net/http"
	"os"
	"reflect"

	"golang.org/x/crypto/argon2"
)

// respondClient send back response to client along with the http status code.
func respondClient(writer http.ResponseWriter, code int, resp []byte) {
	writer.WriteHeader(code)
	if code != http.StatusNoContent {
		if _, err := writer.Write(resp); err != nil {
			logging.MPMLogger.Error(err)
		}
	}
}

func decodeClientMessage(body io.ReadCloser, writer http.ResponseWriter) (credentials, error) {
	decoder := json.NewDecoder(body)
	var creds credentials
	err := decoder.Decode(&creds)
	if err != nil {
		logging.MPMLogger.Error(err)
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte("400 Bad Request"))
		return creds, err
	}

	return creds, nil
}

func storeCredentials(creds credentials) error {
	logging.MPMLogger.Infof("Registering user %s\n", creds.Username)
	randNum := rand.Uint32()
	salt := make([]byte, 4)
	binary.LittleEndian.PutUint32(salt, randNum)
	key := argon2.IDKey([]byte(creds.Password), salt, 1, 64*1024, 4, 32)

	createDataBaseDirectory()

	storeUser, err := json.Marshal(credentialStorageStructure{
		Username: creds.Username,
		Password: append(salt, key...),
	})
	if err != nil {
		logging.MPMLogger.Errorf("Failed to create user %s. Reason: %v\n",
			creds.Username, err)
		return err
	}

	storeUser = append(storeUser, []byte("\n")...)

	if err = writeToDatabase("db/users", storeUser); err != nil {
		logging.MPMLogger.Errorf("Failed to create user %s. Reason: %v",
			creds.Username, err)
		return err
	}

	return nil
}

func verifyLogin(creds credentials, writer http.ResponseWriter) error {
	storedCreds, err := loadCredentials(creds.Username)
	if err != nil {
		switch err.(type) {
		case *UserDoesNotExist:
			writer.WriteHeader(http.StatusUnauthorized)
			writer.Write([]byte("Authentication failed. Invalid username or password"))
		default:
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write([]byte("500 Server Error"))
		}
		return err
	}

	key := argon2.IDKey([]byte(creds.Password), storedCreds.Password[0:4], 1, 64*1024, 4, 32)
	if !reflect.DeepEqual(key, storedCreds.Password[4:]) {
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte("Authentication failed. Invalid username or password"))
		return NewAuthenticationFailed(errors.New("password does not match"))
	}

	return nil
}

func loadCredentials(user string) (credentialStorageStructure, error) {
	userDatabaseMutex.Lock()
	defer userDatabaseMutex.Unlock()
	file, err := os.Open("db/users")
	if err != nil {
		return credentialStorageStructure{},
			NewUserDoesNotExist(err)
	}
	defer file.Close()

	// Start reading from the file with a reader.
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadBytes(10)
		if err != nil && err == io.EOF {
			break
		} else if err != nil {
			return credentialStorageStructure{}, err
		}

		var creds credentialStorageStructure
		json.Unmarshal(line, &creds)

		if creds.Username == user {
			return creds, nil
		}
	}

	return credentialStorageStructure{},
		NewUserDoesNotExist(errors.New("user does not exist"))
}

// Store the secrets of a user in a file.
func storeUserSecrets(creds credentials) error {
	hasSecrets := true
	secrets, err := getUserSecrets(creds.Username)
	var secretStorage secretStorageStructure
	if err != nil {
		switch err.(type) {
		case *os.PathError:
			secretStorage.Username = creds.Username
			if secretStorage.SecretList, err = encryptMap([]byte(creds.Password), creds.SecretList); err != nil {
				return err
			}
			hasSecrets = false
		case *NoSecrets:
			secretStorage.Username = creds.Username
			if secretStorage.SecretList, err = encryptMap([]byte(creds.Password), creds.SecretList); err != nil {
				return err
			}
			hasSecrets = false
		default:
			return err
		}
	} else {
		secretStorage = secrets
		for k, v := range creds.SecretList {
			// Do not re-encrypt the values that have already been added to the
			// database.
			if _, ok := secretStorage.SecretList[k]; !ok {
				ciphertext, err := encryptAESGCM([]byte(creds.Password), []byte(v))
				if err != nil {
					return err
				}
				secretStorage.SecretList[k] = ciphertext
			}
		}
	}

	createDataBaseDirectory()
	mstoreSecrets, err := json.Marshal(secretStorage)
	mstoreSecrets = append(mstoreSecrets, []byte("\n")...)
	if err != nil {
		return err
	}

	if err = updateSecretsDatabase(creds.Username, mstoreSecrets, hasSecrets); err != nil {
		return err
	}

	return nil
}

func getUserSecrets(user string) (secretStorageStructure, error) {
	secretDatabaseMutex.Lock()
	defer secretDatabaseMutex.Unlock()
	file, err := os.Open("db/secrets")
	if err != nil {
		return secretStorageStructure{}, err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadBytes(10)
		if err != nil && err == io.EOF {
			break
		} else if err != nil {
			return secretStorageStructure{}, err
		}

		var secrets secretStorageStructure
		json.Unmarshal(line, &secrets)

		if secrets.Username == user {
			return secrets, nil
		}
	}

	return secretStorageStructure{}, NewNoSecrets(errors.New("user has no secrets"))
}

func updateSecretsDatabase(user string, data []byte, hasSecrets bool) error {
	var database []byte

	secretDatabaseMutex.Lock()
	defer secretDatabaseMutex.Unlock()
	file, err := os.Open("db/secrets")
	if err != nil {
		switch err.(type) {
		case *os.PathError:
			database = data
			hasSecrets = true
		default:
			return err
		}
	} else {
		defer file.Close()

		reader := bufio.NewReader(file)
		for {
			line, err := reader.ReadBytes(10)
			if err != nil && err == io.EOF {
				break
			} else if err != nil {
				return err
			}

			var secrets secretStorageStructure
			json.Unmarshal(line, &secrets)

			if secrets.Username == user {
				database = append(database, data...)
			} else {
				database = append(database, line...)
			}
		}
	}

	// If user does not have secrets stored in the database already, simply
	// append the user data to the database. Otherwise, the database has
	// already been updated in the above steps, so the following line can be
	// skipped
	if !hasSecrets {
		database = append(database, data...)
	}

	if err = writeToDatabase("db/secrets", database); err != nil {
		return err
	}

	return nil
}

// Delete or update all the user's secrets that are listed in the request. Even
// if no secrets were matched with the request, the function will not return
// error. The only exception to this rule is if the user does not exist in the
// secret database (never stored a secret).
func updateUserSecrets(creds credentials, del bool) error {
	secrets, err := getUserSecrets(creds.Username)
	if err != nil {
		return err
	}

	for k, v := range creds.SecretList {
		if del {
			delete(secrets.SecretList, k)
		} else {
			if _, ok := secrets.SecretList[k]; ok {
				ciphertext, err := encryptAESGCM([]byte(creds.Password), []byte(v))
				if err != nil {
					return err
				}
				secrets.SecretList[k] = ciphertext
			}
		}
	}

	mstoreSecrets, err := json.Marshal(secrets)
	mstoreSecrets = append(mstoreSecrets, []byte("\n")...)
	if err != nil {
		return err
	}

	return updateSecretsDatabase(creds.Username, mstoreSecrets, true)
}

// Delete the user's account along with any secrets associated with them.
func deleteAccount(user string) error {
	if err := removeCredentials(user); err != nil {
		return err
	}

	return removeSecrets(user)
}

func removeCredentials(user string) error {
	userDatabaseMutex.Lock()
	defer userDatabaseMutex.Unlock()
	file, err := os.Open("db/users")
	if err != nil {
		return err
	}
	defer file.Close()

	var fileLines []byte
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

		if creds.Username != user {
			fileLines = append(fileLines, line...)
		}
	}

	return writeToDatabase("db/usersdel", fileLines)
}

// Remove secrets associated with the user's account.
func removeSecrets(user string) error {
	hasSecrets := false
	secretDatabaseMutex.Lock()
	defer secretDatabaseMutex.Unlock()
	file, err := os.Open("db/secrets")
	if err != nil {
		return err
	}
	defer file.Close()

	var fileLines []byte
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadBytes(10)
		if err != nil && err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		var secret secretStorageStructure
		json.Unmarshal(line, &secret)

		if secret.Username != user {
			fileLines = append(fileLines, line...)
		} else {
			hasSecrets = true
		}
	}

	// Do not update the secrets database if user has not stored any secrets.
	if hasSecrets {
		err = writeToDatabase("db/secrets", fileLines)
	}
	return err
}

// writeToDatabase create or open the database file and
func writeToDatabase(filename string, data []byte) error {
	var f *os.File
	var err error

	if filename == "db/users" {
		userDatabaseMutex.Lock()
		defer userDatabaseMutex.Unlock()
		f, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	} else if filename == "db/secrets" {
		// The parent function always locks the mutex for this
		f, err = os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	} else if filename == "db/usersdel" {
		// The parent function always locks the mutex for this
		f, err = os.OpenFile("db/users", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	} else {
		err = errors.New("unknown database")
	}

	if err != nil {
		return err
	}

	defer f.Close()

	if _, err = f.Write(data); err != nil {
		return err
	}

	return nil
}

func createDataBaseDirectory() {
	dbDirectoryMutex.Lock()
	os.MkdirAll("db", os.ModePerm)
	dbDirectoryMutex.Unlock()
}
