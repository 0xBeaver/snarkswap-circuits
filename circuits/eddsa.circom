include "../node_modules/circomlib/circuits/eddsaposeidon.circom";

template EdDSAinSNARK() {
    // Signal definitions
    /** Private inputs */
    signal input note;
    signal input pubKey[2];
    signal private input R8x;
    signal private input R8y;
    signal private input s;
    component eddsa = EdDSAPoseidonVerifier()
    eddsa.enabled <== 1;
    eddsa.M <== note;
    eddsa.Ax <== pubKey[0];
    eddsa.Ay <== pubKey[1];
    eddsa.R8x <== R8x;
    eddsa.R8y <== R8y;
    eddsa.S <== s;
}

component main = EdDSAinSNARK();
