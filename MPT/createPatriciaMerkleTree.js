import process from 'process';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
var config =require('../config.json');
let crypto = require('crypto');
const util = require('util');
const { MerkleTree } = require('merkletreejs')
const SHA256 = require('crypto-js/sha256')
const SHA512 = require('crypto-js/sha512')
const SHA3 = require('crypto-js/sha3')
const generateKey = util.promisify(crypto.generateKey);
const createKeccakHash = require('keccak')
// const generateKey = util.promisify(crypto.generateKey);
// import { SecureTrie as Trie } from 'merkle-patricia-tree'// We import the library required to create a Secure Merkle Patricia Tree
import { BaseTrie as Trie} from "merkle-patricia-tree";

const {createHash} = await import('node:crypto');

let h = await crypto.getHashes();
// console.log("Available hash algorithms..");
// console.log(h);

export const CryptoSHAValue = async (node,key = undefined) => {
    if (!key){ // genero un nonce casuale
        key = crypto.randomBytes(config.merklePatriciaTree.keyLength).toString('base64'); // creazione del nonce
    }

    let hashedLeaves,hash
    switch (config.merklePatriciaTree.HLeaves){
        case "keccak256":
            // console.log("keccak function HLeaves: " + node )
            hashedLeaves= createKeccakHash(config.merklePatriciaTree.HLeaves).update(node+key).digest('hex')
            // console.log(hashedLeaves);
            break;
        case "sha3-256":
            // console.log("sha3-256 function HLeaves")
            hash = createHash(config.merklePatriciaTree.HLeaves);
            // console.log("hash " + hash)
            hash.update(node+key)
            hashedLeaves=hash.digest('hex')
            // console.log("hashedLeaves " + hashedLeaves)
            break;
        case "sha3-512":
            // console.log("sha3-512 function HLeaves")
            hash= createHash(config.merklePatriciaTree.HLeaves);
            // console.log("hash " + hash)
            hash.update(node+key)
            hashedLeaves=hash.digest('hex')
            // console.log("hashedLeaves " + hashedLeaves)
            break;
    }

    // console.log("creazione hashed value")
    // console.log(hashedLeaves)
    return {hashedValue:hashedLeaves,nonce:key} //concateno un nonce generato random alla fine della foglia
}

export const CryptoSHAKey = async (key) => {
    let hashedKey,hash=null
    switch (config.merklePatriciaTree.HTree){
        case "keccak256":
             // console.log("keccak function HTREE:" )
            // console.log(config.merklePatriciaTree.HTree)
            hashedKey= createKeccakHash(config.merklePatriciaTree.HTree).update(key).digest('hex')
             // console.log(hashedKey);
            break;
        case "sha3-256":
            // console.log("sha3-256 function HTREE")
            hash = createHash(config.merklePatriciaTree.HTree);
            hash.update(key)
            hashedKey=hash.digest('hex')
            break;
        case "sha3-512":
            // console.log("sha3-512 function HTREE")
            hash = createHash(config.merklePatriciaTree.HTree);
            hash.update(key)
            hashedKey=hash.digest('hex')
            break;
    }
    return hashedKey;
}

export const createPatriciaMerkleTree = async (credAttrName, credAttrValue) => {
    var trie = await new Trie()

    var proof =[]
    var hashedKey
    var nonce ={}
    let obj ={}


    // Inserisco le coppie key:value nel trie
    for(let i=0;i<credAttrValue.length;i++){
        obj=await CryptoSHAValue(credAttrValue[i]) //return hashing del valore + nonce
        /* console.log("valore HASHATO" +i)
         console.log(obj.hashedValue)*/
        nonce[credAttrName[i]] = obj.nonce // memorizzo il nonce della chiave
        // keyHashed.push(obj.hashedValue) // lista delle chiavi hashate + nonce

        // hashing della chiave
        if(config.merklePatriciaTree.HTree!= 'none') {
            // console.log("Hashing della KEY con keccak")
            hashedKey = await CryptoSHAKey(credAttrName[i])
            await trie.put(Buffer.from(hashedKey), Buffer.from(obj.hashedValue)) // inserisco nel Trie la coppia <key,valueHashed> -- key viene hashata
            // console.log(credAttrName[i])
            // console.log(hashedKey)
        }
        else{ // chiave in chiaro
            // console.log("KEY in chiaro(none)")
            await trie.put(Buffer.from(credAttrName[i]), Buffer.from(obj.hashedValue)) // inserisco nel Trie la coppia <key,valueHashed> -- key in chiaro
            // console.log(credAttrName[i])
        }
    }
    // creo la proof per ogni coppia e la converto nel formato string
    for(let i=0; i<credAttrName.length ; i++){
        if (config.merklePatriciaTree.HTree!= 'none'){
            // console.log("Formazione proof " + credAttrName.length)
            // console.log(hashedKey)
            let hashedKeyProof = await CryptoSHAKey(credAttrName[i])
            proof[credAttrName[i]]=(await Trie.createProof(trie,Buffer.from(hashedKeyProof))) // creo la proof
            //console.log(proof[credAttrName[i]])
            proof[credAttrName[i]]=convertToString(proof[credAttrName[i]]) // converte i nodi della proof in string per compatibilità col jwt
            //console.log(proof[credAttrName[i]])
        }
        else{
            proof[credAttrName[i]]=(await Trie.createProof(trie,Buffer.from(credAttrName[i]))) // creo la proof
            //console.log(proof[credAttrName[i]])
            proof[credAttrName[i]]=convertToString(proof[credAttrName[i]]) // converte i nodi della proof in string per compatibilità col jwt
            //console.log(proof[credAttrName[i]])
        }

    }
    return {root:trie.root , proof: proof, nonce:nonce}
}

// Metodo che converte ogni nodo della lista proof da buffer a string per renderlo compatibile con formato jwt
const convertToString = (list) =>{ // input lista dei nodi
    let proof = []
    for(let elem of list) {
        proof.push(elem.toString('base64'))
    }
    return proof
}
