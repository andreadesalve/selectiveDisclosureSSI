import { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyPresentation,  verifyCredential, normalizeCredential, validateCredentialPayload } from 'did-jwt-vc';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
var config =require('../config.json');

const options = {		
    header: {
        "typ": "JWT",
        "alg": "ES256K"
    },
};

// Functionalities for BBS+
const generateBls12381G2KeyPair = require("@mattrglobal/bbs-signatures").generateBls12381G2KeyPair
const blsSign = require("@mattrglobal/bbs-signatures").blsSign
const blsVerify = require("@mattrglobal/bbs-signatures").blsVerify
const blsCreateProof = require("@mattrglobal/bbs-signatures").blsCreateProof
const blsVerifyProof = require("@mattrglobal/bbs-signatures").blsVerifyProof
const blskeypair_uni = await generateBls12381G2KeyPair(Uint8Array.from(Buffer.from(config.mnemonic, "utf-8")));

let claims = [];
let bssSig;

async function createVCPayload(user,nClaims) {
    const VCPayload={};
    var credAttrName =[];
    var credAttrValue =[];
    //VCPayload['sub']=user.did;
    //VCPayload['nbf']=626105238;
    VCPayload['vc']= {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        credentialSubject: {},
    };
    for (let i = 0; i < nClaims; i++) {
        claims.push(Uint8Array.from(Buffer.from("attrName" + i + ":attrValue" + i, "utf-8")));}
        const bbs_signature = await blsSign({
            keyPair: blskeypair_uni,
            messages: claims
        });
    
    VCPayload["vc"]["credentialSubject"]["bbsPublicKey"] = blskeypair_uni.publicKey;
    VCPayload["vc"]["credentialSubject"]["bbsSignature"] = bbs_signature;
    bssSig= bbs_signature;
    return VCPayload;
}

async function createVPPayload(jwt,disclosedClaims,bbs_signature){
	let disclosed_claims = [];  // The sub-array of claims to disclose
    let disclosed_idx = [];      // The array of the indeces of the claims to disclose
    const bbs_nonce = Uint8Array.from(Buffer.from("nonce", "utf-8"));

    for (let c = 0; c < disclosedClaims; c++) {
    	disclosed_claims.push(claims[c]);
        disclosed_idx.push(c);
    }

    const bbs_proof = await blsCreateProof({
        signature: bbs_signature,
        publicKey: blskeypair_uni.publicKey,
        messages: claims, 
        nonce: bbs_nonce,
        revealed: disclosed_idx
    });

    const VCPayload={};
    VCPayload['vp']= {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        verifiableCredential: [jwt]
    };

    VCPayload["vp"]["attributes"] = disclosed_claims;
    VCPayload["vp"]["bbsProof"] = bbs_proof;
    VCPayload["vp"]["bbsNonce"] = bbs_nonce;
    return VCPayload;
}
 

export async function issueVC(issuer,subject,nClaims){
    claims = [];
    let start = performance.now();
    const VCPayload = await createVCPayload(subject,Math.pow(2, nClaims));
    const jwt = await createVerifiableCredentialJwt(VCPayload, issuer, options);
    let end = performance.now();
    const time = (end-start);
    return {jwt,time};
}

export async function verifyVC(jwt,didResolver){
    let start = performance.now();
    const verifiedCredential= await verifyCredential(jwt, didResolver,{});
    let end = performance.now();
    const time = (end-start);
    return time;
}

export async function issueVP(jwt,disclosedClaims, subject){
    let start = performance.now();
    let VPPayload= await createVPPayload(jwt,disclosedClaims,bssSig);
    let jwtVP=await createVerifiablePresentationJwt(VPPayload,subject,options);
    let end = performance.now();
    const time = (end-start);
    return {jwtVP,time};
}


export async function verifyVP(jwtVP,didResolver){
    let start = performance.now();
    const verifiedPresentation= await verifyPresentation(jwtVP, didResolver,{});
    let unverifiedVCs = verifiedPresentation.verifiablePresentation.verifiableCredential;
    const verifiedVP = verifiedPresentation.verifiablePresentation;

    const received_bbs_proof = Uint8Array.from(Object.values(verifiedPresentation.verifiablePresentation.vp.bbsProof));
            const received_nonce = Uint8Array.from(Object.values(verifiedPresentation.verifiablePresentation.vp.bbsNonce));
            const vp_claims = verifiedPresentation.verifiablePresentation.vp.attributes;
            let received_claims = [];
            for(let claim of vp_claims) {
                received_claims.push(Uint8Array.from(Object.values(claim)))
            }

            const received_credential = verifiedPresentation.verifiablePresentation.verifiableCredential[0];
            const received_bbs_public_key = Uint8Array.from(Object.values(received_credential.credentialSubject.bbsPublicKey));

            let a = await blsVerifyProof({
                proof: received_bbs_proof,
                publicKey: received_bbs_public_key,
                messages: received_claims,
                nonce: received_nonce
            })

            if(a.verified == false) {
                console.log("BBS+ not verified")
                console.log(a.error)
            }         
    let end = performance.now();
    const time = (end-start);
    return time;
}