package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/user"
	"regexp"

	"golang.org/x/net/idna"
)

const shortUsage = `Usage of mktls:
  Provide certificates with SAN's'.
  $ mktls myservice.default.svc 127.0.0.1

  Provide certificates with SAN's' and expiry (in 10 years).
  $ mktls -expiryYears 10 myservice.default.svc 127.0.0.1

`

func main() {
	flag.Parse()
	var args = flag.Args()

	var (
		expiryYears = flag.Int("expiryYears", 0, "")
	)
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), shortUsage)
	}

	if len(args) == 0 {
		flag.Usage()
		return
	}

	(&TlsCerts{expiryYears: *expiryYears}).Run(args)
}

func getUserAndHostname() string {
	var userAndHostname string

	u, err := user.Current()
	if err == nil {
		userAndHostname = u.Username + "@"
	}
	if h, err := os.Hostname(); err == nil {
		userAndHostname += h
	}
	if err == nil && u.Name != "" && u.Name != u.Username {
		userAndHostname += " (" + u.Name + ")"
	}

	return userAndHostname
}

func (c *TlsCerts) Run(args []string) {
	if c.expiryYears == 0 {
		c.expiryYears = 10
	}

	hostnameRegexp := regexp.MustCompile(`(?i)^(\*\.)?[0-9a-z_-]([0-9a-z._-]*[0-9a-z_-])?$`)

	for i, name := range args {
		if ip := net.ParseIP(name); ip != nil {
			continue
		}

		if uriName, err := url.Parse(name); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			continue
		}

		asciiHost, err := idna.ToASCII(name)
		if err != nil {
			log.Printf("ERROR: %q is not a valid hostname, IP or URL: %s", name, err)
		}

		args[i] = asciiHost
		if !hostnameRegexp.MatchString(asciiHost) {
			log.Printf("ERROR: %q is not a valid hostname, IP or URL: %s", name, err)
		}
	}

	c.CreateCerts(args)
	fmt.Print(c.Jsonify())
}

func fatalIfErr(err error, msg string) {
	if err != nil {
		log.Fatalf("ERROR: %s: %s", msg, err)
	}
}
