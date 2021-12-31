server:
	cargo run

server/no-mtls:
	cargo run -- --no-mtls

curl:
	curl --cert ./tls/client.pem --key ./tls/client-key.pem --cacert ./tls/ca.pem https://127.0.0.1:3000