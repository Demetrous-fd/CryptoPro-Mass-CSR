package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	cades "github.com/Demetrous-fd/CryptoPro-Adapter"
	"golang.org/x/exp/slog"
)

type ContainerInfo struct {
	Name          string `json:"name"`
	Thumbprint    string `json:"thumbprint"`
	ContainerName string `json:"containerName"`
	ContainerPin  string `json:"containerPin,omitempty"`
	Exportable    bool   `json:"exportable"`
}

func ExecuteCsrInstall(x509 *cades.X509EnrollmentRoot, csr *CsrParams) *ContainerInfo {
	result := &ContainerInfo{}
	csrData, err := generateCsr(x509, csr)
	if err != nil {
		slog.Error(fmt.Sprintf("Cant generate csr request, container[%s], error: %s", csr.Container.Name, err.Error()))
		return result
	}

	outputFolder := *outputFolderFlag
	if !*flatFlag {
		outputFolder = filepath.Join(outputFolder, csr.Container.Name)

		if _, err := os.Stat(outputFolder); errors.Is(err, os.ErrNotExist) {
			os.Mkdir(outputFolder, os.ModePerm)
		}
	}

	csrFilename := fmt.Sprintf("%s.csr", csr.Container.Name)
	csrFilePath := filepath.Join(outputFolder, csrFilename)
	csrFile, err := os.Create(csrFilePath)
	if err != nil {
		slog.Error(fmt.Sprintf("Cant create file: %s, error: %s", csrFilePath, err.Error()))
	}
	csrFile.WriteString(csrData)

	certificate := requestCertificate(csrData)
	if certificate == "" {
		slog.Error(fmt.Sprintf("Cant request certificate, container[%s]", csr.Container.Name))
		return result
	}

	certFilename := fmt.Sprintf("%s.cer", csr.Container.Name)
	certFilePath := filepath.Join(outputFolder, certFilename)
	certFile, err := os.Create(certFilePath)
	if err != nil {
		slog.Error(fmt.Sprintf("Cant create file: %s, error: %s", certFilePath, err.Error()))
	}
	certFile.WriteString(certificate)

	err = installCertificate(x509, certificate)
	if err != nil {
		slog.Error(fmt.Sprintf("Cant install certificate, container[%s], error: %s", csr.Container.Name, err.Error()))
		return result
	}

	cm := cades.CadesManager{}
	container, err := cm.GetContainer(csr.Container.Name)
	if err != nil {
		slog.Error(fmt.Sprintf("Cant get container with name: %s, error: %s", csr.Container.Name, err.Error()))
	}

	if csr.Container.Exportable {
		pfxFilename := fmt.Sprintf("%s.pfx", csr.Container.Name)
		pfxFilePath := filepath.Join(outputFolder, pfxFilename)
		pfxFilePath, _ = filepath.Abs(pfxFilePath)

		if (container != &cades.Container{}) {
			_, err = cm.ExportContainerToPfx(pfxFilePath, container.UniqueContainerName, csr.Container.Pin)
			if err != nil {
				slog.Error(fmt.Sprintf("Cant create file: %s, error: %s", pfxFilePath, err.Error()))
			}
		}
	}

	slog.Info(fmt.Sprintf("Container[%s] and certificate installed", csr.Container.Name))

	result.Name = csr.Container.Name
	certThumbprint, err := getThumbprintFromBS64Certificate(certificate)
	if err != nil {
		slog.Error(err.Error())
	}
	result.Thumbprint = certThumbprint
	result.ContainerName = container.ContainerName
	result.ContainerPin = csr.Container.Pin
	result.Exportable = csr.Container.Exportable
	return result
}

func InstallRoot(cadesObj *cades.Cades) {
	rootCertificate := requestRootCertificate()
	if rootCertificate == "" {
		slog.Error("The root certificate could not be requested")
		return
	}

	thumbprint, err := getThumbprintFromBS64Certificate(rootCertificate)

	if err == nil {
		cm := cades.CadesManager{}
		exists, _ := cm.IsCertificateExists(thumbprint, "uRoot")

		if !exists {
			err := installRootCertificate(cadesObj, rootCertificate)
			if err != nil {
				slog.Error(fmt.Sprintf("Cant install root certificate, error: %s", err.Error()))
			} else {
				slog.Info("Installed root certificate")
			}
		}
	}
}
