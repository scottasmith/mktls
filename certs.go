package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"time"
)

func (c *TlsCerts) CreateCerts(hosts []string) {
	c.caPrivateKey, c.caCertificateBytes, c.caCertificate = generateCA(c.expiryYears)

	c.daemonPrivateKey, c.daemonCertificateBytes = generateCertificate(
		c.caPrivateKey,
		c.caCertificate,
		c.expiryYears,
		false,
		hosts)

	c.clientPrivateKey, c.clientCertificateBytes = generateCertificate(
		c.caPrivateKey,
		c.caCertificate,
		c.expiryYears,
		true,
		[]string{},
	)
}

func (c *TlsCerts) Jsonify() string {
	daemonPrivateDER, err := x509.MarshalPKCS8PrivateKey(c.daemonPrivateKey)
	fatalIfErr(err, "failed to encode daemon private key")

	clientPrivateDER, err := x509.MarshalPKCS8PrivateKey(c.clientPrivateKey)
	fatalIfErr(err, "failed to encode daemon private key")

	response := &JsonResponse{
		ExpiryYears: c.expiryYears,
		CaCert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.caCertificateBytes})),

		DaemonKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: daemonPrivateDER})),
		DaemonCert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.daemonCertificateBytes})),

		ClientKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientPrivateDER})),
		ClientCert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.clientCertificateBytes})),
	}

	responseBytes, err := json.Marshal(response)
	fatalIfErr(err, "failed to marshal JSON")

	return string(responseBytes)
}

func generateCA(expiryYears int) (crypto.PrivateKey, []byte, *x509.Certificate) {
	privateKey, err := generateKey(true)
	fatalIfErr(err, "failed to generate the CA key")
	publicKey := privateKey.(crypto.Signer).Public()

	spkiASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	fatalIfErr(err, "failed to encode public key")

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}

	_, err = asn1.Unmarshal(spkiASN1, &spki)
	fatalIfErr(err, "failed to decode public key")

	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)

	var userAndHostname = getUserAndHostname()
	tpl := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		Subject: pkix.Name{
			Organization:       []string{"mktls CA"},
			OrganizationalUnit: []string{userAndHostname},
			CommonName:         "mktls " + userAndHostname,
		},
		SubjectKeyId: skid[:],

		// NotAfter might as well be same as certificate as both will be re-created
		NotAfter:  time.Now().AddDate(expiryYears, 0, 0),
		NotBefore: time.Now(),

		KeyUsage: x509.KeyUsageCertSign,

		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	certificate, err := x509.CreateCertificate(rand.Reader, tpl, tpl, publicKey, privateKey)
	fatalIfErr(err, "failed to generate CA certificate")

	fatalIfErr(err, "failed to encode CA key")

	return privateKey, certificate, tpl
}

func generateCertificate(
	caPrivateKey crypto.PrivateKey,
	caCertificate *x509.Certificate,
	expiryYears int,
	isClient bool,
	hosts []string,
) (crypto.PrivateKey, []byte) {
	privateKey, err := generateKey(false)
	fatalIfErr(err, "failed to generate certificate key")
	publicKey := privateKey.(crypto.Signer).Public()

	expiration := time.Now().AddDate(expiryYears, 0, 0)

	certStruct := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		Subject: pkix.Name{
			Organization:       []string{"mktls certificate"},
			OrganizationalUnit: []string{getUserAndHostname()},
		},

		NotBefore: time.Now(), NotAfter: expiration,

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			certStruct.IPAddresses = append(certStruct.IPAddresses, ip)
		} else if uriName, err := url.Parse(h); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			certStruct.URIs = append(certStruct.URIs, uriName)
		} else {
			certStruct.DNSNames = append(certStruct.DNSNames, h)
		}
	}

	if isClient {
		certStruct.ExtKeyUsage = append(certStruct.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}

	if len(certStruct.IPAddresses) > 0 || len(certStruct.DNSNames) > 0 || len(certStruct.URIs) > 0 {
		certStruct.ExtKeyUsage = append(certStruct.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	certificate, err := x509.CreateCertificate(rand.Reader, certStruct, caCertificate, publicKey, caPrivateKey)
	fatalIfErr(err, "failed to generate certificate")

	return privateKey, certificate
}

func generateKey(rootCA bool) (crypto.PrivateKey, error) {
	if rootCA {
		return rsa.GenerateKey(rand.Reader, 3072)
	}
	return rsa.GenerateKey(rand.Reader, 2048)
}

func randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	fatalIfErr(err, "failed to generate serial number")
	return serialNumber
}
