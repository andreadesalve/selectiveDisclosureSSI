import {createMerkleTree} from './creationMekleTree.js'
import{verifyAttributes,verifyCompressedAttributes} from './verifyAttributes.js'
import {MerkleTree} from "merkletreejs";
import zlib from "zlib";
import { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyPresentation,  verifyCredential, normalizeCredential, validateCredentialPayload } from 'did-jwt-vc';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
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
    var cred =[];

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
        cred.push(attrName + ":" + attrValue)

      // cred.push({attrName,attrValue})// oggetto dove vengono inseriti tutti gli attributi che diventeranno nodi hashati del merkle tree
        // disclosure.set(attrName,attrValue) // memorizzo gli attributi in chiaro
    }

    // console.log("la lista delle cred è : ")
    // console.log(cred);
    const newMerkleTree = await createMerkleTree(cred); // (attributi da criptare) --> restituisce un oggetto contenente (path nodi per proof, root del merkle tree}
    VCPayload['vc']['credentialSubject']['root']= newMerkleTree.rootTree; // si salva la root del merkle tree 
    disclosure={ clearValueList: cred, proof:newMerkleTree.proof, nonce:newMerkleTree.nonceLeaves} // utile per quando farò la disclosure delle claims nella VP
    //console.log(disclosure);
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
    //console.log("CreateVP: "+nClaims);
     if (nClaims===disclosure.clearValueList.length) { // caso in cui devo rivelare tutti gli attributi 

        for(var elem of disclosure.clearValueList){
            VCPayload['vp']['attributes'].push(elem) // inserisco l'elemento <chiave:valore> in chiaro del nodo foglia
            var name = elem.split(':',1); // recupero la chiave della coppia attrName,attrValue --> attrName
            var listPathNodes = MerkleTree.marshalProof(disclosure.proof[name]) // Returns proof array as JSON string
            /*console.log("--------")
            console.log(name)
            console.log("memoria " +memorySizeOf(listPathNodes))
            console.log("--------")*/
            // var listPathNodes=disclosure.proof[name] // inserisco in listPathNodes il path completo dei nodi utili per ottenere la radice (proof)
            var nonceLeaves= disclosure.nonce[name]
            var obj=  {name , listPathNodes, nonceLeaves}
            // console.log("obj")
            // console.log(obj)
            VCPayload['vp']['proof'].push(obj) // inserisco nella lista l'oggetto formato dal valore in chiaro e la proof per quel valore
         
        }
         // console.log(VCPayload['vp']['proof'])
     }
    else{ // prendo attributi a caso, se il numero di claims da rivelare != dal numero di attributi totali

         // console.log("Numero di Claims da hashare: " + nClaims)
        for (let i = 0; i < nClaims; i++) {
            //const size= disclosure.clearValueList.length - 1
            //const rand = Math.random()
            //let i = size * rand // indice dell'attributo selezionato random
            let attrValue = disclosure.clearValueList[Math.floor(i)]
            var name = (disclosure.clearValueList[Math.floor(i)]).split(':',1).pop();
            var listPathNodes = MerkleTree.marshalProof(disclosure.proof[name]) // Returns proof array as JSON string

            // var listPathNodes=disclosure.proof[name]
            var nonceLeaves= disclosure.nonce[name]
            let obj = {name, listPathNodes, nonceLeaves}
            VCPayload['vp']['attributes'].push(attrValue)
            VCPayload['vp']['proof'].push(obj)
        }
    }
    //console.log(VCPayload);
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
     if (nClaims===disclosure.clearValueList.length) { // caso in cui devo rivelare tutti gli attributi 

        for(var elem of disclosure.clearValueList){
            VCPayload['vp']['attributes'].push(elem) // inserisco l'elemento <chiave:valore> in chiaro del nodo foglia (attrNAme0:attrvalue0)
            var name = elem.split(':',1); // recupero la chiave della coppia attrName,attrValue --> attrName
            // console.log("proof dell'elemento " + elem)
            // console.log(disclosure.proof[name] )
            let listPathNodes = MerkleTree.marshalProof(disclosure.proof[name]) // Returns proof array as JSON string
            var nonceLeaves= disclosure.nonce[name]
            // console.log(nonceLeaves)
            var obj=  {name , listPathNodes, nonceLeaves}
            // console.log("obj")
            // console.log(obj)
            VCPayload['vp']['proof'].push(obj) // inserisco nella lista l'oggetto formato dal valore in chiaro e la proof per quel valore
         
        }
         // console.log(VCPayload['vp']['proof'])


     }
    else{ // prendo attributi a caso, se il numero di claims da rivelare != dal numero di attributi totali

         // console.log("Numero di Claims da hashare: " + nClaims)
        for (let i = 0; i < nClaims; i++) {
            const size= disclosure.clearValueList.length - 1
            const rand = Math.random()
            let i = size * rand // indice dell'attributo selezionato random
            let attrValue = disclosure.clearValueList[Math.floor(i)]
            var name = (disclosure.clearValueList[Math.floor(i)]).split(':',1).pop();
            let listPathNodes = MerkleTree.marshalProof(disclosure.proof[name]) // Returns proof array as JSON string
            var nonceLeaves= disclosure.nonce[name]
            let obj = {name, listPathNodes, nonceLeaves}
            VCPayload['vp']['attributes'].push(attrValue)
            VCPayload['vp']['proof'].push(obj)
        }
    }
    //console.log(VCPayload['vp']['proof']);
    let proofJS=JSON.stringify(VCPayload['vp']['proof']);
    //console.log(proofJS);
      var listPathNodes = zlib.brotliCompressSync(proofJS,{params: {
      [zlib.constants.BROTLI_PARAM_MODE]: zlib.constants.BROTLI_MODE_TEXT
    }}) // applicazione algoritmo di compressione sulla proof
      //console.log(listPathNodes);
      VCPayload['vp']['proof']=listPathNodes.toString('base64') // view a string per compatibilità con jwt
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
    const VPPayload=createVPPayload(jwt,disclosedClaims);
    let jwtVP=await createVerifiablePresentationJwt(VPPayload,subject,options);
    let end = performance.now();
    const time = (end-start);
    return {jwtVP,time};
}


export async function issueCompressedVP(jwt,disclosedClaims, subject){
    let start = performance.now();
    const VPPayload=createCompressedVPPayload(jwt,disclosedClaims);
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
