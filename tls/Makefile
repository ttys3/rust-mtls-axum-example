ca:
	cfssl genkey -initca csr.json | cfssljson -bare ca

cert/server:
	echo '{}' | cfssl gencert -ca ca.pem -ca-key ca-key.pem -config=cfssl.json \
    -hostname="example.localhost,localhost,127.0.0.1" - | cfssljson -bare server
	echo "convert ECC key to PKCS8"
	openssl pkcs8 -topk8 -nocrypt -in server-key.pem -out server-key-pkcs8.pem

cert/client:
	echo '{}' | cfssl gencert -ca ca.pem -ca-key ca-key.pem -config=cfssl.json \
    -hostname="client.localhost,localhost,127.0.0.1" - | cfssljson -bare client
