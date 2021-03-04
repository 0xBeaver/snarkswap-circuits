#!/bin/sh

# create artifacts directory
mkdir -p $(dirname "$0")/../artifacts
cd $(dirname "$0")/../artifacts

snarkjs zkey export verificationkey ../ptau/phase2/eddsa_final.zkey eddsa.vk.json
snarkjs zkey export verificationkey ../ptau/phase2/swap_final.zkey swap.vk.json

echo "THIS IS A TESTING PURPOSE SAMPLE KEY. DON'T USE THIS IN PRODUCTION ENV.\n"