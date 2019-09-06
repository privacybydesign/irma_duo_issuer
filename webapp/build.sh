#!/bin/bash

if [ $# -ne 1 ]; then
	echo "Usage: $0 [language]"
	exit 1
fi

cd "$(dirname "$0")"
mkdir -p ./build
mkdir -p ./build/assets

cp ./$1/index.html ./build/
cp ./$1/messages.js ./build/assets/
cp ./common.js ./build/assets/
cp ./common.css ./build/assets/
cp ./node_modules/bootstrap/dist/css/bootstrap.min.css ./build/assets/
cp ./node_modules/jquery/dist/jquery.min.js ./build/assets/
cp ./node_modules/@privacybydesign/irmajs/dist/irma.js ./build/assets/
