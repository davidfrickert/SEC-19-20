#!/bin/bash

# Key generator
# Run this in the 'keys' folder to generate 10 client keys and 1 server key

mkdir -p "public/clients"
mkdir -p "private/clients"

nkeys=10
if [ "$#" -eq 1 ]; then
  nkeys="$1"
fi
for i in $(seq 1 "$nkeys"); do
	openssl genrsa -out "keypair$i.pem" 4096 
  openssl rsa -in "keypair$i.pem" -pubout -outform DER -out "public/clients/pub$i.der"
	openssl pkcs8 -topk8 -inform PEM -outform DER -in "keypair$i.pem" -out "private/clients/private$i.der" -nocrypt
	rm "keypair$i.pem"
done

openssl genrsa -out "keypair-server.pem" 4096
openssl rsa -in "keypair-server.pem" -pubout -outform DER -out "public/pub-server.der"
openssl pkcs8 -topk8 -inform PEM -outform DER -in "keypair-server.pem" -out "private/priv-server.der" -nocrypt
rm "keypair-server.pem"


