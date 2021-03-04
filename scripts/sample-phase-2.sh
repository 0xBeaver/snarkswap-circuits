#!/bin/sh

# create artifacts directory
mkdir -p $(dirname "$0")/../ptau/phase2
cd $(dirname "$0")/../ptau/phase2

snarkjs zkey new ../../artifacts/eddsa.r1cs ../phase1/pot14_final.ptau eddsa_0.zkey
echo "ENTROPY 1" | snarkjs zkey contribute eddsa_0.zkey eddsa_1.zkey --name="Beaver 1" -v
snarkjs zkey verify ../../artifacts/eddsa.r1cs ../phase1/pot14_final.ptau eddsa_1.zkey
snarkjs zkey beacon eddsa_1.zkey eddsa_final.zkey 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon phase2"
snarkjs zkey verify ../../artifacts/eddsa.r1cs ../phase1/pot14_final.ptau eddsa_final.zkey
snarkjs zkey export verificationkey eddsa_final.zkey ../../artifacts/eddsa_verification_key.json

snarkjs zkey new ../../artifacts/swap.r1cs ../phase1/pot14_final.ptau swap_0.zkey
echo "ENTROPY 2" | snarkjs zkey contribute swap_0.zkey swap_1.zkey --name="Beaver 2" -v
snarkjs zkey verify ../../artifacts/swap.r1cs ../phase1/pot14_final.ptau swap_1.zkey
snarkjs zkey beacon swap_1.zkey swap_final.zkey 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon phase2"
snarkjs zkey verify ../../artifacts/swap.r1cs ../phase1/pot14_final.ptau swap_final.zkey
snarkjs zkey export verificationkey swap_final.zkey ../../artifacts/swap_verification_key.json