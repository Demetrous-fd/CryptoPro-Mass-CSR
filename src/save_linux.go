//go:build !windows
// +build !windows

package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"

	cades "github.com/Demetrous-fd/CryptoPro-Adapter"
	cp "github.com/otiai10/copy"
)

var CONTAINER_FOLDER = regexp.MustCompile(`(?m).{8}\.\d\d\d`)

func SaveContainerToDisk(rootFolder, containerName string) (string, error) {
	cm := cades.CadesManager{}
	container, err := cm.GetContainer(containerName)
	if err != nil {
		return "", err
	}

	containerFolderName := CONTAINER_FOLDER.FindString(container.UniqueContainerName)
	username, err := GetUsername()
	if err != nil {
		return "", err
	}

	containersRoot := fmt.Sprintf(`/var/opt/cprocsp/keys/%s`, username)

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

func GetUsername() (string, error) {
	u, err := user.Current()
	if nil != err {
		return "", err
	}
	return u.Username, nil
}
