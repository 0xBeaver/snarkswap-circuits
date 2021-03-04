#!/bin/sh

# create artifacts directory
mkdir -p $(dirname "$0")/../ptau/phase1
cd $(dirname "$0")/../ptau/phase1

# new powers of taw - constraints 14 => 
snarkjs powersoftau new bn128 14 pot14_0000.ptau -v
# contribution 1
echo "ENTROPY 1" | snarkjs powersoftau contribute pot14_0000.ptau pot14_0001.ptau --name="CONTRIBUTION" -v
# verification of ptau
snarkjs powersoftau verify pot14_0001.ptau
# random beacon
snarkjs powersoftau beacon pot14_0001.ptau pot14_beacon.ptau 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon"
snarkjs powersoftau prepare phase2 pot14_beacon.ptau pot14_final.ptau -v