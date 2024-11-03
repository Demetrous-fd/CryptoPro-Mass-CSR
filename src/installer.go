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
	Name            string `json:"name"`
	Thumbprint      string `json:"thumbprint,omitempty"`
	ContainerName   string `json:"containerName,omitempty"`
	ContainerPin    string `json:"containerPin,omitempty"`
	ContainerFolder string `json:"containerFolder,omitempty"`
	Exportable      bool   `json:"exportable"`
}

func ExecuteCsrInstall(x509 *cades.X509EnrollmentRoot, csr *CsrParams, params *Params) *ContainerInfo {
	cm := cades.CadesManager{}
	result := &ContainerInfo{}
	csrData, err := generateCsr(x509, csr)
	if err != nil {
		slog.Error(fmt.Sprintf("Cant generate csr request, container[%s], error: %s", csr.Container.Name, err.Error()))
		return result
	}

	var outputFolder string
	if params.OutputFolder == "" {
		outputFolder = *outputFolderFlag
	} else {
		outputFolder = params.OutputFolder
	}

	if !*params.Flat {
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

	container, err := cm.GetContainer(csr.Container.Name)
	if err != nil {
		slog.Error(fmt.Sprintf("Cant get container with name: %s, error: %s", csr.Container.Name, err.Error()))
	}

	containerFolderPath, err := SaveContainerToDisk(outputFolder, csr.Container.Name)
	if err != nil {
		slog.Error(fmt.Sprintf("Cant copy container: %s, error: %s", csr.Container.Name, err.Error()))
	}
	result.ContainerFolder = filepath.Base(containerFolderPath)

	if *params.SkipStore {
		defer cm.DeleteContainer(container)
	}

	if *params.SkipCSRRequest {
		result.Name = csr.Container.Name
		result.ContainerPin = csr.Container.Pin
		result.Exportable = csr.Container.Exportable

		if !*params.SkipStore {
			result.ContainerName = container.ContainerName
		}
		slog.Info(fmt.Sprintf("Container[%s] installed", csr.Container.Name))
		return result
	}

	certificate := requestCertificate(csrData, params)
	if certificate == "" {
		slog.Error(fmt.Sprintf("Cant request certificate, container[%s]", csr.Container.Name))
		cm.DeleteContainer(container)
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
		cm.DeleteContainer(container)
		return result
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
	result.ContainerPin = csr.Container.Pin
	result.Exportable = csr.Container.Exportable

	certThumbprint, err := getThumbprintFromBS64Certificate(certificate)
	if err != nil {
		slog.Error(err.Error())
	} else {
		result.Thumbprint = certThumbprint
	}

	if *params.SkipStore {
		defer cm.DeleteCertificate(certThumbprint)
	}

	if !*params.SkipStore {
		result.ContainerName = container.ContainerName
	}
	return result
}

func InstallRoot(cadesObj *cades.Cades, params *Params) {
	rootCertificate := requestRootCertificate(params)
	if rootCertificate == "" {
		slog.Error("The root certificate could not be requested")
		return
	}

	cerFilename := "cryptopro_ca.cer"
	cerFilePath := filepath.Join(params.OutputFolder, cerFilename)
	cerFile, err := os.Create(cerFilePath)
	if err != nil {
		slog.Error(fmt.Sprintf("Cant create file: %s, error: %s", cerFilePath, err.Error()))
	}
	cerFile.WriteString(rootCertificate)

	if *params.SkipStore {
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
