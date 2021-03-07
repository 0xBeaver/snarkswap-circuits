const chai = require("chai");
const path = require("path");
const tester = require("circom").tester;
const { buildBn128 } = require("ffjavascript");
const circomlib = require("circomlib");

const eddsa = circomlib.eddsa;
const assert = chai.assert;

describe("Swap SNARK test", function () {
  let circuit;
  let bn128;
  let Fr;

  this.timeout(100000);

  before(async () => {
    bn128 = await buildBn128();
    Fr = bn128.Fr
    circuit = await tester(path.join(__dirname, "../circuits", "eddsa.circom"));
  });
  after(async () => {
    await bn128.terminate();
  });

  it("Sign a single number", async () => {
    const msg = 1234n;
    const prvKey = Buffer.from(
      "0001020304050607080900010203040506070809000102030405060708090001",
      "hex"
    );
    const pubKey = eddsa.prv2pub(prvKey);
    const signature = eddsa.signPoseidon(prvKey, msg);
    assert(eddsa.verifyPoseidon(msg, signature, pubKey));
    const input = {
      note: msg,
      pubKey: pubKey,
      R8x: signature.R8[0],
      R8y: signature.R8[1],
      s: signature.S,
    };

    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);
  });

  it("Detect Invalid signature", async () => {
    const msg = 1234n;

    const prvKey = Buffer.from(
      "0001020304050607080900010203040506070809000102030405060708090001",
      "hex"
    );

    const pubKey = eddsa.prv2pub(prvKey);
    const signature = eddsa.signPoseidon(prvKey, msg);
    assert(eddsa.verifyPoseidon(msg, signature, pubKey));
    try {
      const w = await circuit.calculateWitness(
        {
          note: msg,
          pubKey: pubKey,
          R8x: signature.R8[0] + 1n,
          R8y: signature.R8[1],
          s: signature.S,
        },
        true
      );
      assert(false);
    } catch (err) {
      assert(/Constraint\sdoesn't\smatch(.*)1\s!=\s0/.test(err.message));
    }
  });
});
