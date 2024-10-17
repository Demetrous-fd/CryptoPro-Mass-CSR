package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	cades "github.com/Demetrous-fd/CryptoPro-Adapter"
	"golang.org/x/exp/slog"
)

const CAPICOM_STORE_OPEN_READ_WRITE = 1

func requestRootCertificate() string {
	client := http.Client{}
	certUri := "https://testgost2012.cryptopro.ru/certsrv/certnew.cer?ReqID=CACert&Renewal=-1&Enc=b64"

	resp, err := client.Get(certUri)
	if err != nil {
		slog.Debug(fmt.Sprintf("Failed request to %s, error: %s", certUri, err.Error()))
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		slog.Debug(fmt.Sprintf("The root certificate could not be requested, status_code: %d", resp.StatusCode))
		return ""
	}

	cert, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Debug(fmt.Sprintf("Cant read response, error: %s", err.Error()))
		return ""
	}

	certData := string(cert)
	return certData
}

func getThumbprintFromBS64Certificate(data string) (string, error) {
	rootCertificateDer := strings.ReplaceAll(data, "-----BEGIN CERTIFICATE-----\r\n", "")
	rootCertificateDer = strings.ReplaceAll(rootCertificateDer, "-----END CERTIFICATE-----\r\n", "")

	certificate, err := base64.StdEncoding.DecodeString(rootCertificateDer)
	if err != nil {
		slog.Debug(err.Error())
		return "", err
	}
	fingerprint := sha1.Sum(certificate)

	var buf bytes.Buffer
	for _, f := range fingerprint {
		fmt.Fprintf(&buf, "%02X", f)
	}
	thumbprint := strings.ToLower(buf.String())
	return thumbprint, nil
}

func installRootCertificate(cadesObj *cades.Cades, certificateData string) error {

	certificate, err := cades.NewCertificate(cadesObj)
	if err != nil {
		return err
	}

	certificate.Import(certificateData)

	store, err := cades.NewStore(cadesObj)
	if err != nil {
		return err
	}
	defer store.Close()

	err = store.Open(cades.CAPICOM_CURRENT_USER_STORE, "ROOT", CAPICOM_STORE_OPEN_READ_WRITE)
	if err != nil {
		return err
	}

	err = store.Add(certificate)
	if err != nil {
		return err
	}

	return nil
}
