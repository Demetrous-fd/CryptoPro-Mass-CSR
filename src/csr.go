package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	cades "github.com/Demetrous-fd/CryptoPro-Adapter"
	"github.com/google/uuid"
	"golang.org/x/exp/slog"
)

const (
	ContextUser                            = 0x1
	XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE   = 0x10
	XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE    = 0x20
	XCN_CERT_NON_REPUDIATION_KEY_USAGE     = 0x40
	XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE   = 0x80
	XCN_CRYPT_HASH_INTERFACE               = 0x2
	XCN_CRYPT_STRING_BASE64                = 1
	XCN_CERT_NAME_STR_ENABLE_PUNYCODE_FLAG = 2097152
	XEKL_KEYSPEC_KEYX                      = 1
	ALLOW_UNTRUSTED_ROOT                   = 4
	XCN_CRYPT_STRING_BINARY                = 0x2
)

var (
	CERT_REQUEST_ID_PATTERN = regexp.MustCompile(`(?m)ReqID=\d*&`)
)

type Container struct {
	Name          string `json:"name,omitempty"`
	Exportable    bool   `json:"exportable,omitempty"`
	KeySpec       *int   `json:"keySpec,omitempty"`
	KeyProtection int    `json:"keyProtection,omitempty"`
	Pin           string `json:"pin,omitempty"`
}

type CsrParams struct {
	ExtensionEKU     []string            `json:"extensionEKU,omitempty"`
	EKUKeyUsageFlags *int                `json:"ekuKeyUsageFlags,omitempty"`
	ProviderName     string              `json:"providerName,omitempty"`
	Container        Container           `json:"container,omitempty"`
	SAN              map[string][]string `json:"san,omitempty"`
	Dn               map[string]string   `json:"dn"`
}

func generateCsr(x509 *cades.X509EnrollmentRoot, params *CsrParams) (string, error) {
	informations, err := x509.CCspInformations()
	if err != nil {
		return "", err
	}

	err = informations.AddAvailableCsps()
	if err != nil {
		return "", err
	}

	if params.ProviderName == "" {
		params.ProviderName = "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider"
	}

	status, err := informations.GetCspStatusFromProviderName(params.ProviderName, XEKL_KEYSPEC_KEYX)
	if err != nil {
		return "", err
	}

	algorithm, err := status.CspAlgorithm()
	if err != nil {
		return "", err
	}

	defaultKeyLength, err := algorithm.DefaultLength()
	if err != nil {
		return "", err
	}

	information, err := status.CspInformation()
	if err != nil {
		return "", err
	}

	providerType, err := information.Type()
	if err != nil {
		return "", err
	}

	// Private Key
	pk, err := x509.CX509PrivateKey()
	if err != nil {
		return "", err
	}

	if params.Container.KeySpec == nil {
		_, err = pk.SetKeySpec(1)
	} else {
		_, err = pk.SetKeySpec(*params.Container.KeySpec)
	}
	if err != nil {
		return "", err
	}

	_, err = pk.SetProviderName(params.ProviderName)
	if err != nil {
		return "", err
	}

	_, err = pk.SetProviderType(providerType)
	if err != nil {
		return "", err
	}

	_, err = pk.SetKeyProtection(params.Container.KeyProtection)
	if err != nil {
		return "", err
	}

	_, err = pk.SetLength(defaultKeyLength)
	if err != nil {
		return "", err
	}

	_, err = pk.SetMachineContext(false)
	if err != nil {
		return "", err
	}

	if params.Container.Name == "" {
		id := uuid.New()
		params.Container.Name = fmt.Sprintf("TEST_%s", id.String())
	}

	_, err = pk.SetContainerName(params.Container.Name)
	if err != nil {
		return "", err
	}

	if params.Container.Exportable {
		_, err = pk.SetExportPolicy(1)
		if err != nil {
			return "", err
		}
	} else {
		_, err = pk.SetExportPolicy(0)
		if err != nil {
			return "", err
		}
	}

	if params.Container.Pin != "" {
		_, err = pk.SetPin(params.Container.Pin)
		if err != nil {
			return "", err
		}
	}

	request, err := x509.CX509CertificateRequestPkcs10()
	if err != nil {
		return "", err
	}

	err = request.InitializeFromPrivateKey(1, *(*cades.CadesObject)(pk), "")
	if err != nil {
		return "", err
	}

	// Extension Key Usage
	eku, err := x509.CX509ExtensionKeyUsage()
	if err != nil {
		return "", err
	}

	if params.EKUKeyUsageFlags == nil {
		defaultValue := XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE |
			XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE |
			XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE |
			XCN_CERT_NON_REPUDIATION_KEY_USAGE

		params.EKUKeyUsageFlags = &defaultValue
	}

	err = eku.InitializeEncode(*params.EKUKeyUsageFlags)
	if err != nil {
		return "", err
	}

	ext, err := request.X509Extensions()
	if err != nil {
		return "", err
	}

	err = ext.Add((*cades.CX509Extension)(eku))
	if err != nil {
		return "", err
	}

	// Subject
	subjectInfo := dnToX500DistinguishedName(params.Dn)
	oDn, err := x509.CX500DistinguishedName()
	if err != nil {
		return "", err
	}

	err = oDn.Encode(subjectInfo, XCN_CERT_NAME_STR_ENABLE_PUNYCODE_FLAG)
	if err != nil {
		return "", err
	}

	_, err = request.SetSubject(oDn)
	if err != nil {
		return "", err
	}

	// Enhanced Key Usage
	oids, err := x509.CObjectIds()
	if err != nil {
		return "", err
	}

	if len(params.ExtensionEKU) <= 0 {
		params.ExtensionEKU = []string{
			"1.3.6.1.5.5.7.3.2",
		}
	}

	for _, oid := range params.ExtensionEKU {
		oidObject, err := x509.CObjectId()
		if err != nil {
			return "", err
		}

		err = oidObject.InitializeFromValue(oid)
		if err != nil {
			return "", err
		}

		err = oids.Add(oidObject)
		if err != nil {
			return "", err
		}
	}

	eeku, err := x509.CX509ExtensionEnhancedKeyUsage()
	if err != nil {
		return "", err
	}

	err = eeku.InitializeEncode(oids)
	if err != nil {
		return "", err
	}

	ext2, err := request.X509Extensions()
	if err != nil {
		return "", err
	}

	err = ext2.Add((*cades.CX509Extension)(eeku))
	if err != nil {
		return "", err
	}

	// Subject alternative name
	if len(params.SAN) != 0 {
		cadesVersion, err := cades.GetCadesVersion(x509.Cades)
		if err != nil {
			return "", err
		}

		pluginVersion, err := cades.GetPluginVersion(x509.Cades)
		if err != nil {
			return "", err
		}

		// КриптоПро CSP 5.0 R4 (сборка 5.0.13300 Uroboros) или новей
		// КриптоПро ЭЦП Browser plug-in сборка 2.0.15260 или новей
		if (cadesVersion.Major >= 5 && cadesVersion.Minor >= 0 && cadesVersion.Build >= 13300) &&
			(pluginVersion.Build >= 2 && pluginVersion.Minor >= 0 && pluginVersion.Build >= 15260) {
			altNames, err := x509.CAlternativeNames()
			if err != nil {
				return "", err
			}

			for oid, values := range params.SAN {
				for _, value := range values {
					objId, err := x509.CObjectId()
					if err != nil {
						return "", err
					}

					err = objId.InitializeFromValue(oid)
					if err != nil {
						return "", err
					}

					altName, err := x509.CAlternativeName()
					if err != nil {
						return "", err
					}

					err = altName.InitializeFromOtherName(objId, XCN_CRYPT_STRING_BINARY, value, true)
					if err != nil {
						return "", err
					}

					err = altNames.Add(altName)
					if err != nil {
						return "", err
					}
				}
			}

			extAltNames, err := x509.CX509ExtensionAlternativeNames()
			if err != nil {
				return "", err
			}

			err = extAltNames.InitializeEncode(altNames)
			if err != nil {
				return "", err
			}

			ext3, err := request.X509Extensions()
			if err != nil {
				return "", err
			}

			err = ext3.Add((*cades.CX509Extension)(extAltNames))
			if err != nil {
				return "", err
			}
		} else {
			slog.Debug(fmt.Sprintf("CadesVersion: %+v", cadesVersion))
			slog.Debug(fmt.Sprintf("PluginVersion: %+v", pluginVersion))
			slog.Warn("Использование SAN(Subject alternative name) доступно с версии КриптоПро CSP 5.0 R4 (сборка 5.0.13300 Uroboros) и КриптоПро ЭЦП Browser plug-in сборка 2.0.15260")
		}
	}

	// Getting hash algorithm
	CspInformations, _ := x509.CCspInformations()
	CspInformations.AddAvailableCsps()

	oCspInformation, _ := CspInformations.ItemByName(params.ProviderName)
	CspAlgorithms, _ := oCspInformation.CspAlgorithms()
	algCount, _ := CspAlgorithms.Count()

	var hashAlgorithmOid *cades.CObjectId
	for nIndex := 0; nIndex < algCount; nIndex++ {
		CspAlgorithm, _ := CspAlgorithms.ItemByIndex(nIndex)
		aType, _ := CspAlgorithm.Type()
		if XCN_CRYPT_HASH_INTERFACE == aType {
			algorithmOid, _ := CspAlgorithm.GetAlgorithmOid(0, 0)
			name, _ := algorithmOid.FriendlyName()
			value, _ := algorithmOid.Value()

			if name != "" && value != "" {
				hashAlgorithmOid = algorithmOid
			}
		}
	}

	if (hashAlgorithmOid == &cades.CObjectId{}) {
		return "", fmt.Errorf("hashAlgorithmOid not found for provider: %s", params.ProviderName)
	}

	_, err = request.SetHashAlgorithm(hashAlgorithmOid)
	if err != nil {
		return "", err
	}

	// Enrollment
	enroll, err := x509.CX509Enrollment()
	if err != nil {
		return "", err
	}

	err = enroll.InitializeFromRequest(request)
	if err != nil {
		return "", err
	}

	csr, err := enroll.CreateRequest(XCN_CRYPT_STRING_BASE64)
	if err != nil {
		return "", err
	}

	return csr, nil
}

func dnToX500DistinguishedName(dn map[string]string) string {
	var parts []string
	for key, value := range dn {
		escapedValue := strings.ReplaceAll(value, `"`, `""`)
		parts = append(parts, fmt.Sprintf("%s=\"%s\"", key, escapedValue))
	}
	return strings.Join(parts, ";")
}

func requestCertificate(csr string, params *Params) string {
	client := http.Client{}
	formData := url.Values{}
	formData.Add("Mode", "newreq")
	formData.Add("ThumbPrint", "")
	formData.Add("TargetStoreFlags", "0")
	formData.Add("SaveCert", "yes")
	formData.Add("CertRequest", csr)

	encodeData := formData.Encode()
	uri := fmt.Sprintf("https://%s/certsrv/certfnsh.asp", *params.CA.Url)
	request, _ := http.NewRequest(
		"POST", uri, strings.NewReader(encodeData),
	)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(request)
	if err != nil {
		slog.Debug(fmt.Sprintf("Failed request to %s, error: %s", uri, err.Error()))
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Debug(fmt.Sprintf("Cant read response, error: %s", err.Error()))
		return ""
	}

	data := string(body)
	requestId := CERT_REQUEST_ID_PATTERN.FindString(data)
	if requestId == "" {
		slog.Debug("RequestId not found")
		return ""
	}

	certUri := fmt.Sprintf("https://%s/certsrv/certnew.cer?%sEnc=b64", *params.CA.Url, requestId)
	resp, err = client.Get(certUri)
	if err != nil {
		slog.Debug(fmt.Sprintf("Failed request to %s, error: %s", certUri, err.Error()))
		return ""
	}
	defer resp.Body.Close()

	cert, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Debug(fmt.Sprintf("Cant read response, error: %s", err.Error()))
		return ""
	}

	certData := string(cert)
	return certData
}

func installCertificate(x509 *cades.X509EnrollmentRoot, certificateData string) error {
	enrollCert, err := x509.CX509Enrollment()
	if err != nil {
		return err
	}

	err = enrollCert.Initialize(ContextUser)
	if err != nil {
		return err
	}

	certificateData = strings.ReplaceAll(certificateData, "-----BEGIN CERTIFICATE-----\r\n", "")
	certificateData = strings.ReplaceAll(certificateData, "-----END CERTIFICATE-----\r\n", "")

	err = enrollCert.InstallResponse(ALLOW_UNTRUSTED_ROOT, certificateData, XCN_CRYPT_STRING_BASE64, "")
	if err != nil {
		return err
	}

	return nil
}
