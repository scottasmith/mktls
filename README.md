# mktls

mktls simply returns a JSON array of daemon and client certificates

```
$ mktls example.com "*.example.com" example.test localhost 127.0.0.1 ::1
{
  "expiryYears": 10,
  "caCert": "...",
  "daemonPrivateKey": "...", 
  "daemonCertificate: "...",
  "clientPrivateKey": "...",
  "clientCertificate": "..."
}

$ mktls -expiryYears 2 example.com "*.example.com" example.test localhost 127.0.0.1 ::1
{
  "expiryYears": 2
  "caCert": "...",
  "daemonPrivateKey": "...", 
  "daemonCertificate: "...",
  "clientPrivateKey": "...",
  "clientCertificate": "..."
}
```

# purpose

This was written to be consumed by using automation tools such as ansible.

It is HUGELY based on https://github.com/FiloSottile/mkcert and 
