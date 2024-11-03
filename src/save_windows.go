//go:build windows
// +build windows

package main

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	cades "github.com/Demetrous-fd/CryptoPro-Adapter"
	cp "github.com/otiai10/copy"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var CONTAINER_FOLDER = regexp.MustCompile(`(?m).{8}\.\d\d\d`)

func SaveContainerToDisk(rootFolder, containerName string) (string, error) {
	cm := cades.CadesManager{}
	container, err := cm.GetContainer(containerName)
	if err != nil {
		return "", err
	}

	if strings.Contains(container.ContainerName, "REGISTRY") {
		return SaveContainerFromRegistry(rootFolder, containerName)
	} else {
		return SaveContainerFromFolder(rootFolder, container)
	}
}

func SaveContainerFromFolder(rootFolder string, container *cades.Container) (string, error) {
	containerFolderName := CONTAINER_FOLDER.FindString(container.UniqueContainerName)
	username, err := GetUsername()
	if err != nil {
		return "", err
	}

	containersRoot := fmt.Sprintf(`C:\Users\%s\AppData\Local\Crypto Pro`, username)
	newContainerPath := filepath.Join(rootFolder, containerFolderName)
	containerPath := filepath.Join(containersRoot, containerFolderName)
	if _, err := os.Stat(containerPath); err != nil {
		return "", err
	}

	err = cp.Copy(containerPath, newContainerPath)
	if err != nil {
		return "", err
	}

	return newContainerPath, nil
}

func SaveContainerFromRegistry(rootFolder, containerName string) (string, error) {
	var keyPathPrefix string
	var keyPath string
	rootPath := registry.LOCAL_MACHINE

	if runtime.GOARCH == "amd64" {
		keyPathPrefix = `SOFTWARE\WOW6432Node`
	} else {
		keyPathPrefix = `SOFTWARE`
	}

	isAdmin := IsAdmin()
	if isAdmin {
		keyPath = fmt.Sprintf(`%s\Crypto Pro\Settings\Keys\%s`, keyPathPrefix, containerName)
	} else {
		sid, err := GetUserSid()
		if err != nil {
			return "", err
		}

		keyPath = fmt.Sprintf(`%s\Crypto Pro\Settings\Users\%s\Keys\%s`, keyPathPrefix, sid, containerName)
	}

	exists := KeyExists(rootPath, keyPath)
	if !exists {
		return "", os.ErrNotExist
	}

	keys, err := EnumerateValues(rootPath, keyPath)
	if err != nil {
		return "", err
	}

	containerFolderPath := filepath.Join(rootFolder, fmt.Sprintf("%s.000", RandomString(8)))
	if _, err := os.Stat(containerFolderPath); errors.Is(err, os.ErrNotExist) {
		os.Mkdir(containerFolderPath, os.ModePerm)
	}

	for _, key := range keys {
		data, err := ReadBinaryValue(rootPath, keyPath, key)
		if err != nil {
			return "", err
		}

		filePath := filepath.Join(containerFolderPath, key)
		file, err := os.Create(filePath)
		if err != nil {
			return "", err
		}

		file.Write(data)
	}

	return containerFolderPath, nil
}

func RandomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func ReadBinaryValue(root registry.Key, keyPath, valueName string) ([]byte, error) {
	k, err := registry.OpenKey(root, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	value, _, err := k.GetBinaryValue(valueName)
	if err != nil {
		return nil, err
	}

	return value, nil
}

func KeyExists(root registry.Key, keyPath string) bool {
	k, err := registry.OpenKey(root, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func EnumerateValues(root registry.Key, keyPath string) ([]string, error) {
	k, err := registry.OpenKey(root, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	valueNames, err := k.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}

	return valueNames, nil
}

func GetUserSid() (string, error) {
	u, err := user.Current()
	if nil != err {
		return "", err
	}
	return u.Uid, nil
}

func GetUsername() (string, error) {
	u, err := user.Current()
	if nil != err {
		return "", err
	}
	return strings.Split(u.Username, `\`)[1], nil
}

func IsAdmin() bool {
	// https://coolaj86.com/articles/golang-and-windows-and-admins-oh-my/
	var sid *windows.SID

	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)

	if err != nil {
		return false
	}

	token := windows.Token(0)

	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}

	return member
}
