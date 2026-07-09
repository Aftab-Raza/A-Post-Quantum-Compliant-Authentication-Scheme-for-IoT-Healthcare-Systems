#!/bin/bash

echo "Building Official Saber Shared Library..."

gcc -shared -fPIC \
../libs/saber/Reference_Implementation_KEM/pack_unpack.c \
../libs/saber/Reference_Implementation_KEM/poly.c \
../libs/saber/Reference_Implementation_KEM/fips202.c \
../libs/saber/Reference_Implementation_KEM/verify.c \
../libs/saber/Reference_Implementation_KEM/cbd.c \
../libs/saber/Reference_Implementation_KEM/SABER_indcpa.c \
../libs/saber/Reference_Implementation_KEM/kem.c \
../libs/saber/Reference_Implementation_KEM/rng.c \
-o libsaber.so \
-lcrypto

echo "Build Complete!"