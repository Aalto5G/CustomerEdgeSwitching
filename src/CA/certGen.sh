#!/bin/bash
#Shell script for quickly generating self-signed certificates, by Hammad Kabir
echo "Shell script for generating self-signed certificates"

if [ $# -eq 0 ]
then
	echo "Kindly provide arguments as following:"
	echo "./autoCert 'node1.foo. node2.foo.'"
	exit 0
fi

if [ ! -d "CA" ]
then
	echo "CA folder not found"
	res="notFound"
	mkdir CA
fi

res=""

if [ "${res}" == "" ]
then
	mkdir CA
	cd CA
	cafiles="ca.crt ca.key ca.rand"

	for i in $cafiles;
	{
		if [ ! -f "$i" ]
		then
			echo "Pre-checking for CA credentials"
			res="notFound"
			break
		fi
	}
	cd ..

fi

# Check if any of the CA certificate files are missing

if [ "${res}" == "notFound" ];
then
	echo "Creating self-signed CA credentials ... "
	openssl rand -out CA/ca.rand 2048
	openssl genrsa -rand CA/ca.rand -out CA/ca.key 2048
	openssl req -x509 -new -key CA/ca.key -out CA/ca.crt -days 7300 -subj '/C=FI/ST=Uusimaa/L=Espoo/O=Aalto/CN=cesCA'
fi

for i in $1;
{
	echo $i
	mkdir $i
	privKey=${i}key
	csrFile=${i}req
	crt=${i}crt

	openssl genrsa -rand ca.rand -out $i/$privKey 2048
	openssl req -new -out $i/$csrFile -key $i/$privKey -subj '/C=US/ST=Uusimaa/L=Espoo/O=Aalto/CN='$i
	openssl x509 -req -in $i/$csrFile -out $i/$crt -CAkey CA/ca.key -CA CA/ca.crt -days 365 -CAcreateserial -CAserial serial
	# Removing the client CSR - (certificate signing request)
	rm $i/$csrFile
	# Copy CA certificate to client directory 
	cp CA/ca.crt $i/
}

echo "Client certificates are issued"


