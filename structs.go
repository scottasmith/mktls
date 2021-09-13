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
	ExpiryYears int `json:"expiryYears"`
	CaCert string `json:"caCert"`

	DaemonKey  string `json:"daemonKey"`
	DaemonCert string `json:"daemonCert"`

	ClientKey  string `json:"clientKey"`
	ClientCert string `json:"clientCert"`
}
