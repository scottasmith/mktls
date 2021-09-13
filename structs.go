package main

import (
	"crypto"
	"crypto/x509"
)

type TlsCertser interface {
	Run(args []string)

	CreateCerts(args []string)

	Jsonify() string
}

type TlsCerts struct {
	expiryYears int

	caPrivateKey       crypto.PrivateKey
	caCertificateBytes []byte
	caCertificate      *x509.Certificate

	daemonPrivateKey       crypto.PrivateKey
	daemonCertificateBytes []byte

	clientPrivateKey       crypto.PrivateKey
	clientCertificateBytes []byte
}

type JsonResponse struct {
	CaCert string

	DaemonKey  string
	DaemonCert string

	ClientKey  string
	ClientCert string
}
