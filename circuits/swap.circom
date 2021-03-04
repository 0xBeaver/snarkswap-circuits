// SPDX-License-Identifier: GPL-3.0-or-later
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/mux2.circom";

template Swap() {
    signal input sourceA;
    signal input sourceB;
    signal input reserve0;
    signal input reserve1;
    signal input mask;
    signal input hRatio;
    signal input hReserve0;
    signal input hReserve1;
    signal input ratioSalt;
    signal input outputA;
    signal input outputB;
    signal input address0;
    signal input address1;
    signal input feeNumerator;
    signal input feeDenominator;

    // notes[0]: token address
    // notes[1]: amount
    // notes[2]: pubkey x
    // notes[3]: pubkey y
    // notes[4]: note salt
    signal private input sourceADetails[5];
    signal private input sourceBDetails[5];
    signal private input outputADetails[5];
    signal private input outputBDetails[5];
    signal private input newReserve0;
    signal private input newReserve1;
    signal private input pubkey[2];
    signal private input sigR8[2];
    signal private input sigS;

    // range limit - prevent overflows
    // require(reserve0 < (1<<112));
    component rangeChecker1 = Num2Bits(112);
    component rangeChecker2 = Num2Bits(112);
    component rangeChecker3 = Num2Bits(112);
    component rangeChecker4 = Num2Bits(112);
    component rangeChecker5 = Num2Bits(160);
    component rangeChecker6 = Num2Bits(160);
    component rangeChecker7 = Num2Bits(224);
    component rangeChecker8 = Num2Bits(239);
    component rangeChecker9 = Num2Bits(239);
    component rangeChecker10 = Num2Bits(239);
    component rangeChecker11 = Num2Bits(239);
    rangeChecker1.in <= reserve0;
    rangeChecker2.in <= reserve1;
    rangeChecker3.in <= newReserve0;
    rangeChecker4.in <= newReserve1;
    rangeChecker5.in <= address0;
    rangeChecker6.in <= address1;
    rangeChecker7.in <= mask;
    rangeChecker8.in <= sourceADetails[1];
    rangeChecker9.in <= sourceBDetails[1];
    rangeChecker10.in <= outputADetails[1];
    rangeChecker11.in <= outputBDetails[1];

    // verify note hash
    component sourceAHash = Poseidon(5);
    sourceAHash.inputs[0] <== sourceADetails[0];
    sourceAHash.inputs[1] <== sourceADetails[1];
    sourceAHash.inputs[2] <== sourceADetails[2];
    sourceAHash.inputs[3] <== sourceADetails[3];
    sourceAHash.inputs[4] <== sourceADetails[4];
    sourceAHash.out === sourceA;
    component sourceBHash = Poseidon(5);
    sourceBHash.inputs[0] <== sourceBDetails[0];
    sourceBHash.inputs[1] <== sourceBDetails[1];
    sourceBHash.inputs[2] <== sourceBDetails[2];
    sourceBHash.inputs[3] <== sourceBDetails[3];
    sourceBHash.inputs[4] <== sourceBDetails[4];
    sourceBHash.out === sourceB;
    component outputAHash = Poseidon(5);
    outputAHash.inputs[0] <== outputADetails[0];
    outputAHash.inputs[1] <== outputADetails[1];
    outputAHash.inputs[2] <== outputADetails[2];
    outputAHash.inputs[3] <== outputADetails[3];
    outputAHash.inputs[4] <== outputADetails[4];
    outputAHash.out === outputA;
    component outputBHash = Poseidon(5);
    outputBHash.inputs[0] <== outputBDetails[0];
    outputBHash.inputs[1] <== outputBDetails[1];
    outputBHash.inputs[2] <== outputBDetails[2];
    outputBHash.inputs[3] <== outputBDetails[3];
    outputBHash.inputs[4] <== outputBDetails[4];
    outputBHash.out === outputB;

    // owner of sourceA == owner of sourceB
    // verify signature
    component txHash = Poseidon(5);
    txHash.inputs[0] <== sourceA;
    txHash.inputs[1] <== sourceB;
    txHash.inputs[2] <== outputA;
    txHash.inputs[3] <== outputB;
    txHash.inputs[4] <== ratioSalt;

    sourceADetails[2] === sourceBDetails[2]
    sourceADetails[3] === sourceBDetails[3]
    pubkey[0] === sourceADetails[2];
    pubkey[1] === sourceADetails[3];

    component eddsa = EdDSAPoseidonVerifier()
    eddsa.enabled <== 1;
    eddsa.M <== txHash.out;
    eddsa.Ax <== pubkey[0];
    eddsa.Ay <== pubkey[1];
    eddsa.R8x <== sigR8[0];
    eddsa.R8y <== sigR8[1];
    eddsa.S <== sigS;

    // check hRatio
    component hRatioHash = Poseidon(3);
    hRatioHash.inputs[0] <== newReserve0;
    hRatioHash.inputs[1] <== newReserve1;
    hRatioHash.inputs[2] <== ratioSalt;
    hRatio === hRatioHash.out;

    // source A should be a note for token 0 or token 1
    (sourceADetails[0] - address0) * (sourceADetails[0] - address1) === 0;
    // source B should be a note for token 0 or token 1
    (sourceBDetails[0] - address0) * (sourceBDetails[0] - address1) === 0;

    // check mask validity
    component maskBits = Num2Bits(224);
    component maskValidity[224];
    maskBits.in <== mask;

    component hReserve0Bits = Num2Bits(112);
    component newReserve0Bits = Num2Bits(112);
    hReserve0Bits.in <== hReserve0;
    newReserve0Bits.in <== newReserve0;
    for(var i = 112; i < 224; i ++) {
        maskValidity[i] = ForceEqualIfEnabled();
        maskValidity[i].enabled <== maskBits.out[i] - 1; // disable when bit exists
        maskValidity[i].in[0] <== hReserve0Bits.out[i - 112];
        maskValidity[i].in[1] <== newReserve0Bits.out[i - 112];
    }

    component hReserve1Bits = Num2Bits(112);
    component newReserve1Bits = Num2Bits(112);
    hReserve1Bits.in <== hReserve1;
    newReserve1Bits.in <== newReserve1;
    for(var i = 0; i < 112; i ++) {
        maskValidity[i] = ForceEqualIfEnabled();
        maskValidity[i].enabled <== maskBits.out[i] - 1; // disable when bit exists
        maskValidity[i].in[0] <== hReserve1Bits.out[i];
        maskValidity[i].in[1] <== newReserve1Bits.out[i];
    }

    // make sure no money has been printed
    component isSourceAToken0 = IsEqual()
    isSourceAToken0.in[0] <== sourceADetails[0];
    isSourceAToken0.in[1] <== address0;
    component isSourceBToken0 = IsEqual()
    isSourceBToken0.in[0] <== sourceBDetails[0];
    isSourceBToken0.in[1] <== address0;
    component noteAmountIn0 = Mux2();
    noteAmountIn0.s[0] <== isSourceAToken0.out;
    noteAmountIn0.s[1] <== isSourceBToken0.out;
    noteAmountIn0.c[0] <== 0;
    noteAmountIn0.c[1] <== sourceADetails[1];
    noteAmountIn0.c[2] <== sourceBDetails[1];
    noteAmountIn0.c[3] <== sourceADetails[1] + sourceBDetails[1];

    component isSourceAToken1 = IsEqual()
    isSourceAToken1.in[0] <== sourceADetails[0];
    isSourceAToken1.in[1] <== address1;
    component isSourceBToken1 = IsEqual()
    isSourceBToken1.in[0] <== sourceBDetails[0];
    isSourceBToken1.in[1] <== address1;
    component noteAmountIn1 = Mux2();
    noteAmountIn1.s[0] <== isSourceAToken1.out;
    noteAmountIn1.s[1] <== isSourceBToken1.out;
    noteAmountIn1.c[0] <== 0;
    noteAmountIn1.c[1] <== sourceADetails[1];
    noteAmountIn1.c[2] <== sourceBDetails[1];
    noteAmountIn1.c[3] <== sourceADetails[1] + sourceBDetails[1];

    component isOutputAToken0 = IsEqual()
    isOutputAToken0.in[0] <== outputADetails[0];
    isOutputAToken0.in[1] <== address0;
    component isOutputBToken0 = IsEqual()
    isOutputBToken0.in[0] <== outputBDetails[0];
    isOutputBToken0.in[1] <== address0;
    component noteAmountOut0 = Mux2();
    noteAmountOut0.s[0] <== isOutputAToken0.out;
    noteAmountOut0.s[1] <== isOutputBToken0.out;
    noteAmountOut0.c[0] <== 0;
    noteAmountOut0.c[1] <== outputADetails[1];
    noteAmountOut0.c[2] <== outputBDetails[1];
    noteAmountOut0.c[3] <== outputADetails[1] + outputBDetails[1];

    component isOutputAToken1 = IsEqual()
    isOutputAToken1.in[0] <== outputADetails[0];
    isOutputAToken1.in[1] <== address1;
    component isOutputBToken1 = IsEqual()
    isOutputBToken1.in[0] <== outputBDetails[0];
    isOutputBToken1.in[1] <== address1;
    component noteAmountOut1 = Mux2();
    noteAmountOut1.s[0] <== isOutputAToken1.out;
    noteAmountOut1.s[1] <== isOutputBToken1.out;
    noteAmountOut1.c[0] <== 0;
    noteAmountOut1.c[1] <== outputADetails[1];
    noteAmountOut1.c[2] <== outputBDetails[1];
    noteAmountOut1.c[3] <== outputADetails[1] + outputBDetails[1];

    // if net balance of token0 increases, the net balance of token1 should decrease.
    component isSpendingToken0 = GreaterThan(112); // amountIn0D < amountOut0D;
    component isSpendingToken1 = GreaterThan(112); // amount1n1 < amountOut1D;
    isSpendingToken0.in[0] <== noteAmountIn0.out;
    isSpendingToken0.in[1] <== noteAmountOut0.out;
    isSpendingToken1.in[0] <== noteAmountIn1.out;
    isSpendingToken1.in[1] <== noteAmountOut1.out;
    component tradeValidity = Mux2();
    tradeValidity.c[0] <== 0;
    tradeValidity.c[1] <== 1;
    tradeValidity.c[2] <== 1;
    tradeValidity.c[3] <== 0;
    tradeValidity.s[0] <== isSpendingToken0.out;
    tradeValidity.s[1] <== isSpendingToken1.out;
    tradeValidity.out === 1;

    // x*y = k AMM works
    // fee0D = fee0* Denominator(10000)
    component fee0D = Mux1();
    fee0D.s <== isSpendingToken0.out;
    fee0D.c[0] <== 0;
    fee0D.c[1] <== (noteAmountIn0.out - noteAmountOut0.out)*feeNumerator;


    component fee1D = Mux1();
    fee1D.s <== isSpendingToken1.out;
    fee1D.c[0] <== 0;
    fee1D.c[1] <== (noteAmountIn1.out - noteAmountOut1.out)*feeNumerator;

    signal balance0Adjusted <== (newReserve0*feeDenominator - fee0D.out);
    signal balance1Adjusted <== (newReserve1*feeDenominator - fee1D.out);

    component xyK = GreaterEqThan(252);
    signal reserve0D <== reserve0 * feeDenominator;
    signal reserve1D <== reserve1 * feeDenominator;
    xyK.in[0] <== balance0Adjusted * balance1Adjusted;
    xyK.in[1] <== reserve0D * reserve1D;
    xyK.out === 1;

    // prove no money printed
    component noToken0Print = ForceEqualIfEnabled();
    noToken0Print.enabled <== 1;
    noToken0Print.in[0] <== reserve0 + noteAmountIn0.out;
    noToken0Print.in[1] <== newReserve0 + noteAmountOut0.out;

    // prove no money printed
    component noToken1Print = ForceEqualIfEnabled();
    noToken1Print.enabled <== 1;
    noToken1Print.in[0] <== reserve1 + noteAmountIn1.out;
    noToken1Print.in[1] <== newReserve1 + noteAmountOut1.out;
}

component main = Swap();
