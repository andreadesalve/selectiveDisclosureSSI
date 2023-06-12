import {SymmetricAttributes} from './cipherSymmetricKey.js'
import {verifyAttributes} from './verifyAttributes.js'
import { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyPresentation,  verifyCredential, normalizeCredential, validateCredentialPayload } from 'did-jwt-vc';


let disclosure=new Map();

const options = {
        header: {
            "typ": "JWT",
            "alg": "ES256K"
        },
    };


async function createVCPayload(user,nClaims) {
    const VCPayload={};
    //VCPayload['sub']=user.did;
    //VCPayload['nbf']=626105238;
    VCPayload['vc']= {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        credentialSubject: {},
    };
    for (let i = 0; i < nClaims; i++) {
        var attrName="attrName"+i;
        var attrValue="attrValue"+i;
        const encryAttr = await SymmetricAttributes(attrValue,undefined,undefined ,undefined); // cifro l'attributo con AES-256 e genero una chiave lunga 256 bit
        disclosure.set(attrName,{path:[attrName],key:encryAttr.keyAttr, iv:encryAttr.iv}); // inserisco la tripla <path(attrName),chiave segreta, vettore di inizializzazione>
        VCPayload['vc']['credentialSubject'][attrName] = encryAttr.encryptedData; // sta inserendo nella credenziale l'attributo criptato
    }
    return VCPayload;
}


function createVPPayload(vc,nClaims) {
    // console.log("il numero di claim selezionate è " + nClaims)
    const VCPayload={};
    //VCPayload['sub']=user.did;
    //VCPayload['nbf']=626105238;
    VCPayload['vp']= {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        verifiableCredential: [vc], //stai mettendo le VC (tipo la laurea) firmata dall'università, poi la VP in seguito la firma il subject (Paolo Mori)
    };
    VCPayload['vp']['attributes']=[]; // qui andranno le chiavi segrete e gli iv degli attributi che vogliamo svelare
    if (nClaims==disclosure.size) { // se gli attributi da rivelare sono tutti allora inserisco tutti i valori nell'array VCPayload['vp'] ??
        disclosure.forEach (function(value, key){

            VCPayload['vp']['attributes'].push(value); // verrà inserito l'oggetto contenente la tripla <path(AttributodaDivulgare),chiave segreta,iv>
            // console.log(value);
        });
    }
    else{ // scelgo a caso alcuni attributi da criptare --> selective disclosure
        let keys=Array.from(disclosure.keys()); // ottieni un array di chiavi(attrName) iterabili
        for (let i = 0; i < nClaims; i++) { // itero tante volte quanti sono i claims da criptare e li scelgo a caso dalla lista
            let attN=keys[i]; // prendo a caso una chiave, simulando che sia quello l'attributo da rivelare al verificatore
            // console.log("Gli attributi scelti da svelare sono: " +attN);
            VCPayload['vp']['attributes'].push(disclosure.get(attN));
        }
    }
    return VCPayload;
}


export async function issueVC(issuer,subject,nClaims){
    disclosure=new Map();
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
    const VPPayload=createVPPayload(jwt,disclosedClaims);
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
    const disclosedAttributeVerification = await verifyAttributes(unverifiedVCs, verifiedVP);
    let end = performance.now();
    const time = (end-start);
    return time;
}