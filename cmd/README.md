# Useful commands
> go run . cli gen-ca --organization="My Company" --country="NP --curve=P384 --cn="My Secure CA" --cert=ca.crt --key=ca.key

- This command creates a Certificate Authority (CA) certificate and its private key.
- The CA is the root of trust that signs other certificates.


> go run . cli gen-server --ca=ca.crt --cakey=ca.key --key-type=ECDSA --param=P256 --cn=server.example.com --dns="localhost,server.example.com" --ip="127.0.0.1" --cert=server.crt --key=server.key

- This command generates a server certificate signed by the CA.
- It secures your server (e.g., for TLS/SSL) and includes DNS names and IP addresses.

> go run . cli gen-client --ca=ca.crt --cakey=ca.key --cn=client-user --cert=client.crt --key=client.key

- This command creates a client certificate used for authenticating a user or device.
- It is signed by the CA and uses the efficient Ed25519 algorithm.

> go run . cli gen-code-sign --ca=ca.crt --cakey=ca.key --cn=file-signer --rsa-bits=2048 --cert=code_sign.crt --key=code_sign.key

- This command generates a certificate used for code signing.
- Code signing ensures that software or files come from a trusted source and have not been altered.


> go run . cli gen-crl --ca=ca.crt --cakey=ca.key --revoked="123456789,987654321" --crl=ca.crl

- This command creates a CRL that lists revoked certificates.
- Clients check the CRL to ensure a certificate hasn’t been revoked by the CA.


> go run . cli sign --file=server.crt --key=ca.key --out=server.crt.sig

- This command signs a file (e.g., a certificate) using a private key.
- The signature ensures the file’s integrity and authenticity.


> go run . cli verify --file=server.crt --sig=server.crt.sig --cert=ca.crt

- This command verifies the signature of a file using the public key from a certificate.
- It confirms that the file hasn’t been tampered with.

> go run . cli sign-text --key=ca.key --text="The quick brown fox jumps over the lazy dog." --out=text.sig

- This command signs plain text data using a private key.
- The signature is output in base64 format.


> go run . cli verify-text --cert=ca.crt --text="The quick brown fox jumps over the lazy dog." --sig="$(cat text.sig)"

- This command verifies the signature of plain text using the public key from a certificate.
- Provide the base64–encoded signature.

> go run . cli sign-json --key=ca.key --json='{"name": "Alice", "age": 30, "premium": true}' --out=json.sig

- This command signs JSON data (provided as a JSON string) using a private key.
- The JSON signature is output in base64 format.

> go run . cli verify-json --cert=ca.crt --json='{"name": "Alice", "age": 30, "premium": true}' --sig="$(cat json.sig)"

- This command verifies the signature of JSON data using the public key from a certificate.

> go run . cli inspect --cert=server.crt

- This command displays detailed information about a certificate.

> go run . cli validate --cert=client.crt --ca=ca.crt

- This command validates a client certificate against the CA certificate.
- It ensures that the certificate chain is intact and properly signed.