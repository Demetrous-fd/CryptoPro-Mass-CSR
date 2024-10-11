package main

import (
	"fmt"

	cades "github.com/Demetrous-fd/CryptoPro-Adapter"
	"golang.org/x/exp/slog"
)

func ExecuteCsrInstall(x509 *cades.X509EnrollmentRoot, csr *CsrParams) {
	csrData, err := generateCsr(x509, csr)
	if err != nil {
		slog.Error(fmt.Sprintf("Cant generate csr request, container[%s], error: %s", csr.Container.Name, err.Error()))
		return
	}

	certificate := requestCertificate(csrData)

	if certificate == "" {
		slog.Error(fmt.Sprintf("Cant request certificate, container[%s]", csr.Container.Name))
		return
	}

	err = installCertificate(x509, certificate)
	if err != nil {
		slog.Error(fmt.Sprintf("Cant install certificate, container[%s], error: %s", csr.Container.Name, err.Error()))
		return
	}
	slog.Info(fmt.Sprintf("Container[%s] and certificate installed", csr.Container.Name))
}

func InstallRoot(cadesObj *cades.Cades) {
	rootCertificate := requestRootCertificate()
	if rootCertificate == "" {
		slog.Error("The root certificate could not be requested")
		return
	}

	thumbprint, err := getRootCertificateThumbprint(rootCertificate)

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
