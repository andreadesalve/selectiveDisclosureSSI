import { SecureTrie as Trie } from 'merkle-patricia-tree'
import {createPatriciaMerkleTree} from './createPatriciaMerkleTree.js'
import {verifyAttributes, verifyCompressedAttributes, convertToBufferBase64} from './verifyAttributesPatricia.js'
const require = createRequire(import.meta.url);
import zlib from "zlib";
import { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyPresentation,  verifyCredential, normalizeCredential, validateCredentialPayload } from 'did-jwt-vc';
import { createRequire } from 'module';
var config =require('../config.json');

const { performance } = require('perf_hooks'); // performance suite for time measurement
var disclosure= {};


    const options = {
        header: {
            "typ": "JWT",
            "alg": "ES256K"
        },
    };

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
        var attrName="attrName"+i;
        var attrValue="attrValue"+i;
        credAttrName.push(attrName)
        credAttrValue.push(attrValue)
    }
    const newPatriciaMerkleTree = await createPatriciaMerkleTree(credAttrName,credAttrValue); // (attributi da criptare) --> restituisce un oggetto contenente (path nodi per proof, root del merkle tree}
    VCPayload['vc']['credentialSubject']['root']= newPatriciaMerkleTree.root; // si salva la root del merkle Patricia tree
    disclosure={ clearKeyList:credAttrName, clearValueList: credAttrValue, proof:newPatriciaMerkleTree.proof, nonce:newPatriciaMerkleTree.nonce} // utile per quando farò la disclosure delle claims nella VP

    return VCPayload;
}


function createVPPayload(vc,nClaims) {
    const VCPayload={};
    VCPayload['vp']= {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        verifiableCredential: [vc]
    };

    VCPayload['vp']['attributes']=[]; // qui andranno gli attributi da svelare fatti così attrName0:attrValue0...
    VCPayload['vp']['proof']=[]

    if (nClaims==disclosure.clearKeyList.length) { // caso in cui devo rivelare tutti gli attributi
        for(let i=0;i<disclosure.clearKeyList.length;i++){
            VCPayload['vp']['attributes'].push(disclosure.clearKeyList[i]+":"+disclosure.clearValueList[i]) // inserisco il valore in chiaro del nodo foglia
            let name =disclosure.clearKeyList[i]
            let listPathNodes=disclosure.proof[name] // inserisco in listPathNodes il path completo dei nodi utili per ottenere la radice (proof)
            let nonceValue = disclosure.nonce[name]
            let obj=  { name , listPathNodes, nonceValue}
            VCPayload['vp']['proof'].push(obj) // inserisco nella lista l'oggetto formato dal valore in chiaro e la proof per quel valore
            
        }
    }
   else{ // prendo attributi a caso, se il numero di claims da rivelare != dal numero di attributi totali

        for (let i = 0; i < nClaims; i++) {
            //const size= disclosure.clearValueList.length - 1
            //const rand = Math.random()
            //let i = Math.floor(size * rand) // indice dell'attributo selezionato random
            VCPayload['vp']['attributes'].push(disclosure.clearKeyList[i]+":"+disclosure.clearValueList[i]) // inserisco il valore in chiaro del nodo foglia
            let name =disclosure.clearKeyList[i]
            let listPathNodes=disclosure.proof[name] // inserisco in listPathNodes il path completo dei nodi utili per ottenere la radice (proof)
            let nonceValue = disclosure.nonce[name]
            let obj=  { name , listPathNodes, nonceValue}
            VCPayload['vp']['proof'].push(obj) // inserisco nella lista l'oggetto formato dal valore in chiaro e la proof per quel valore

        }
    }
    return VCPayload;
}


function createCompressedVPPayload(vc,nClaims) {
    const VCPayload={};
    VCPayload['vp']= {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        verifiableCredential: [vc]
    };

    VCPayload['vp']['attributes']=[]; // qui andranno gli attributi da svelare fatti così attrName0:attrValue0...
    VCPayload['vp']['proof']=[]

    if (nClaims==disclosure.clearKeyList.length) { // caso in cui devo rivelare tutti gli attributi
        for(let i=0;i<disclosure.clearKeyList.length;i++){
            VCPayload['vp']['attributes'].push(disclosure.clearKeyList[i]+":"+disclosure.clearValueList[i]) // inserisco il valore in chiaro del nodo foglia
            let name =disclosure.clearKeyList[i]
            let listPathNodes=disclosure.proof[name] // inserisco in listPathNodes il path completo dei nodi utili per ottenere la radice (proof)
            let nonceValue = disclosure.nonce[name]
            let obj=  { name , listPathNodes, nonceValue}
            VCPayload['vp']['proof'].push(obj) // inserisco nella lista l'oggetto formato dal valore in chiaro e la proof per quel valore
            
        }
    }
   else{ // prendo attributi a caso, se il numero di claims da rivelare != dal numero di attributi totali

        for (let i = 0; i < nClaims; i++) {
            VCPayload['vp']['attributes'].push(disclosure.clearKeyList[i]+":"+disclosure.clearValueList[i]) // inserisco il valore in chiaro del nodo foglia
            let name =disclosure.clearKeyList[i]
            let listPathNodes=disclosure.proof[name] // inserisco in listPathNodes il path completo dei nodi utili per ottenere la radice (proof)
            let nonceValue = disclosure.nonce[name]
            let obj=  {name , listPathNodes, nonceValue}
            VCPayload['vp']['proof'].push(obj) // inserisco nella lista l'oggetto formato dal valore in chiaro e la proof per quel valore

        }
    }
     let proofJs= JSON.stringify(VCPayload['vp']['proof']) // 1. trasformo l'array contenente buffer in JSON
     let listPathNodesComp = zlib.brotliCompressSync(proofJs,{
    params: {
      [zlib.constants.BROTLI_PARAM_MODE]: zlib.constants.BROTLI_MODE_TEXT
    }
  }) //2. applicazione algoritmo di compressione sulla proof
  listPathNodesComp=listPathNodesComp.toString('base64') //3. per renderlo compatibile col formato jwt
            //console.log("Final listPathNodesComp: "+listPathNodesComp);
  VCPayload['vp']['proof']=listPathNodesComp;
  //console.log(VCPayload);
  //console.log(VCPayload['vp']['proof']);
  return VCPayload;
}
 

export async function issueVC(issuer,subject,nClaims){
     disclosure= {};
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
    const VPPayload=await createVPPayload(jwt,disclosedClaims);
    let jwtVP=await createVerifiablePresentationJwt(VPPayload,subject,options);
    let end = performance.now();
    const time = (end-start);
    return {jwtVP,time};
}


export async function issueCompressedVP(jwt,disclosedClaims, subject){
    let start = performance.now();
    const VPPayload=await createCompressedVPPayload(jwt,disclosedClaims);
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


export async function verifyVPV2(jwtVP,didResolver){
    let start = performance.now();
    const verifiedPresentation= await verifyPresentation(jwtVP, didResolver,{});
    let end = performance.now();
    const time1 = (end-start);
    let unverifiedVCs = verifiedPresentation.verifiablePresentation.verifiableCredential;
    const verifiedVP = verifiedPresentation.verifiablePresentation;
    start = performance.now();
    const disclosedAttributeVerification = await verifyAttributes(unverifiedVCs, verifiedVP);
     end = performance.now();
    const time2 = (end-start);
    return {time1,time2};
}

export async function verifyCompressedVP(jwtVP,didResolver){
    let start = performance.now();
    const verifiedPresentation= await verifyPresentation(jwtVP, didResolver,{});
    let unverifiedVCs = verifiedPresentation.verifiablePresentation.verifiableCredential;
    const verifiedVP = verifiedPresentation.verifiablePresentation;
    const disclosedAttributeVerification = await verifyCompressedAttributes(unverifiedVCs, verifiedVP);
    let end = performance.now();
    const time = (end-start);
    return time;
}

export async function verifyCompressedVPV2(jwtVP,didResolver){
    let start = performance.now();
    const verifiedPresentation= await verifyPresentation(jwtVP, didResolver,{});
    let end = performance.now();
    const time1 = (end-start);
    let unverifiedVCs = verifiedPresentation.verifiablePresentation.verifiableCredential;
    const verifiedVP = verifiedPresentation.verifiablePresentation;
    start = performance.now();
    const disclosedAttributeVerification = await verifyCompressedAttributes(unverifiedVCs, verifiedVP);
    end = performance.now();
    const time2 = (end-start);
    return {time1,time2};
}