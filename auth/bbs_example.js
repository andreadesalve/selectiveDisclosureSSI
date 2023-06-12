import { createRequire } from 'module';
const require = createRequire(import.meta.url);

const generateBls12381G2KeyPair = require("@mattrglobal/bbs-signatures").generateBls12381G2KeyPair
const blsSign = require("@mattrglobal/bbs-signatures").blsSign
const blsVerify = require("@mattrglobal/bbs-signatures").blsVerify
const blsCreateProof = require("@mattrglobal/bbs-signatures").blsCreateProof
const blsVerifyProof = require("@mattrglobal/bbs-signatures").blsVerifyProof

const messages = [
    Uint8Array.from(Buffer.from("message1", "utf-8")),
    Uint8Array.from(Buffer.from("message2", "utf-8")),
    Uint8Array.from(Buffer.from("message3", "utf-8")),
    Uint8Array.from(Buffer.from("message4", "utf-8")),
    Uint8Array.from(Buffer.from("message5", "utf-8"))        
]

async function test() {

    const keyPair = await generateBls12381G2KeyPair();

    const signature = await blsSign({
        keyPair,
        messages: messages // <= The signature is applied to all the messages
    })

    const isVerified = await blsVerify({
        publicKey: keyPair.publicKey,
        messages: messages,
        signature
    })

    console.log("Verified signature: " + isVerified.verified)

    // Selective disclosure
    const proof = await blsCreateProof({ // <= selective disclosure
        signature,
        publicKey: keyPair.publicKey,
        messages: messages,
        nonce: Uint8Array.from(Buffer.from("nonce", "utf-8")),
        revealed: [2,3]    // <= Indicate the indeces of the messages to reveal
    })

    const isProofVerified = await blsVerifyProof({
        proof,
        publicKey: keyPair.publicKey,
        messages: [messages[2], messages[3]],// <= insert the messages to reveal
        nonce: Uint8Array.from(Buffer.from("nonce", "utf-8"))
    })

    console.log(isProofVerified)
}

test()
