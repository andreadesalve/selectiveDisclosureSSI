import process from 'process';
import { createRequire } from 'module';
import {CryptoSHAKey,CryptoSHAValue} from './createPatriciaMerkleTree.js'
// import { SecureTrie as Trie } from 'merkle-patricia-tree'// We import the library required to create a Secure Merkle Patricia Tree
import { BaseTrie as Trie } from 'merkle-patricia-tree'
import keccak256 from "keccak256";
import {Keccak} from "sha3";
import zlib from "zlib";
const require = createRequire(import.meta.url);
const util = require('util');
const SHA256 = require('crypto-js/sha256')
const SHA512 = require('crypto-js/sha512')
const SHA3 = require('crypto-js/sha3')
const { MerkleTree } = require('merkletreejs')
const createKeccakHash = require('keccak')


let crypto;
var config =require('../config.json');

crypto = require('crypto');


export const verifyAttributes = async (VCs, VP)  => {
    var retrivedVal
    var listHashedKey =[]
    let listValue= VP.vp.attributes
    const listProof = VP.vp.proof
    for(const credential of VCs){
        var credVC = credential.credentialSubject
        var root = credVC["root"] // nodo radice della VC
        // console.log(VCs)
        // console.log(VP)
        for(let i=0;i<listProof.length;i++) { // verifica di tutti gli attributi presenti nella VP
            listProof[i].listPathNodes = convertToBufferBase64(listProof[i].listPathNodes) // converte i nodi della proof da string a buffer
            let keyAttr = listProof[i].name
            let tmp = listValue[i].split(":") // ricavo il valore i-esimo corrispondente alla chiave i-esima
            let value = tmp[1]
            let objHashed = await CryptoSHAValue(value, listProof[i].nonceValue) //// applico l'hashing + nonce al valore per verificarla
            // console.log("verify")
            // console.log(objHashed.hashedValue)
            // console.log("root: " + root)
            // console.log("keyAttr: "+ keyAttr)
            let key = await CryptoSHAKey(keyAttr)
            // console.log("KECCAK: " + key)
            /*  console.log("valore HASHATO " + i)
              console.log(objHashed.hashedValue)*/
            try {
                if(config.merklePatriciaTree.HTree=='none'){
                    // console.log("chiave in chiaro")
                    // console.log(listProof[i].listPathNodes)
                    retrivedVal = await Trie.verifyProof(Buffer.from(root), Buffer.from(keyAttr), listProof[i].listPathNodes)
                }
                else{ // applicazione hashing keccak256 alla key
                    // console.log("chiave hashata")
                    // console.log(listProof[i].listPathNodes)
                    retrivedVal = await Trie.verifyProof(Buffer.from(root), Buffer.from(key), listProof[i].listPathNodes)
                    // console.log("value recuperato: " + retrivedVal)
                }
                // console.log("Il valore dell'attributo verificato è: " + retrivedVal)


                if (objHashed.hashedValue == retrivedVal) {
                    // console.log(Buffer.from(objHashed.hashedValue))
                    // console.log(val)
                    // console.log("Il valore dell'attributo verificato è: " + retrivedVal)
                } else {
                    console.log("Verifica fallita!")
                }
            } catch (e) {
                console.log(e.stack);
                console.log("EXCEPTION: Verifica dell'attributo " + keyAttr + " fallita ");
            }
        }
    }

    return ;
}


export const verifyCompressedAttributes = async (VCs, VP)  => {
    var retrivedVal
    var listProofDecompress =[]
    var listHashedKey =[]
    let listValue= VP.vp.attributes
    const listProof = VP.vp.proof

     let buf = Buffer.from(listProof,"base64");
    let decompression = zlib.brotliDecompressSync(buf) //1. decompressione Proof
    let obj= JSON.parse(decompression.toString("utf8")) //2. trasformo json in oggetto
    //console.log(obj);
    listProofDecompress=obj
    //Buffer.from(obj,'base64');
    //console.log(listProofDecompress);
    //for(let j=0 ; j<obj.length; j++) {
        // console.log(Buffer.from(obj[i]))
    //    listProofDecompress[j] = Buffer.from(obj[j],'base64') // trasformo la proof in array di buffer
    //}
           

    for(const credential of VCs){
        var credVC = credential.credentialSubject
        var root = credVC["root"] // nodo radice della VC
        // console.log(VCs)
        // console.log(VP)
        for(let i=0;i<listValue.length;i++) { // verifica di tutti gli attributi presenti nella VP
            // listProof[i].listPathNodes = convertToBufferBase64(listProof[i].listPathNodes) // converte i nodi della proof da string a buffer
            /*
            NEW
             */
            //console.log("Verify :"+listProof[i].listPathNodesComp);
            //console.log("JSON to obj "+obj)
            /*
            END NEW
             */               
             listProofDecompress[i].listPathNodes = convertToBufferBase64(listProofDecompress[i].listPathNodes)         
            //console.log("verify"+listProofDecompress[i])
            let keyAttr = listProofDecompress[i].name
            //console.log("verify"+keyAttr)
            let tmp = listValue[i].split(":") // ricavo il valore i-esimo corrispondente alla chiave i-esima
            let value = tmp[1]
            let objHashed = await CryptoSHAValue(value, listProofDecompress[i].nonceValue) //// applico l'hashing + nonce al valore per verificarla
            //console.log(objHashed.hashedValue)
            //console.log("root: " + root)
            //console.log("keyAttr: "+ keyAttr)
            let key = await CryptoSHAKey(keyAttr)
            //console.log("KECCAK: " + key)
            //console.log("valore HASHATO " + i)
            //console.log(objHashed.hashedValue)
            try {
                if(config.merklePatriciaTree.HTree=='none'){
                     //console.log("chiave in chiaro");
                     //console.log(listProofDecompress);
                    retrivedVal = await Trie.verifyProof(Buffer.from(root), Buffer.from(keyAttr),  listProofDecompress[i].listPathNodes)
                }
                else{ // applicazione hashing keccak256 alla key
                    // console.log("chiave hashata")
                    // console.log(key)
                    // console.log(listProofDecompress)
                    retrivedVal = await Trie.verifyProof(Buffer.from(root), Buffer.from(key), listProofDecompress[i].listPathNodes)
                    // console.log("value recuperato: " + retrivedVal)
                }
                //console.log("Il valore dell'attributo verificato è: " + retrivedVal)


                if (objHashed.hashedValue == retrivedVal) {
                    // console.log(Buffer.from(objHashed.hashedValue))
                    // console.log(val)
                    // console.log("Il valore dell'attributo verificato è: " + retrivedVal)
                } else {
                    console.log("Verifica fallita!")
                }
            } catch (e) {
                console.log(e.stack)
                console.log("EXCEPTION: Verifica dell'attributo " + keyAttr + " fallita ")
            }
        }
    }

    return ;
}

//Metodo che converte i nodi della proof da string a buffer
export const convertToBufferBase64= (list) =>{
    let proof = []
    for(let elem of list) {
        proof.push(Buffer.from(elem,'base64'))
    }

    return proof
}