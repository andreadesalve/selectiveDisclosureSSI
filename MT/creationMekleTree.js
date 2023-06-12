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
// const keccak256 = require('keccak256')
const createKeccakHash = require('keccak')
// const generateKey = util.promisify(crypto.generateKey);


const {createHash} = await import('node:crypto');




export const CryptoSHALeaves = async (node,key = undefined) => {
    if (!key){ // genero un nonce casuale
        //console.log("creo la chiave")
        key = crypto.randomBytes(config.merkleTree.keyLengthHLeaves).toString('base64'); // creazione del nonce
        // console.log(key)
        // key = await generateKey('hmac', {length: config.merkleTree.keyLengthHLeaves}); // genero un nonce di lunghezza specificata nel file config.json)
        // key = key.export().toString('hex');
    }
    // console.log("key: " + key)
    let hashedLeaves,hash
    switch (config.merkleTree.HLeaves){
        case "keccak256":
            // console.log("keccak function HLeaves: " + node )
            hashedLeaves= createKeccakHash(config.merkleTree.HLeaves).update(node+key).digest('hex')
             // console.log(hashedLeaves);
            break;
        case "sha3-256":
            // console.log("sha3-256 function HLeaves")
            hash = createHash(config.merkleTree.HLeaves);
            // console.log("hash " + hash)
            hash.update(node+key)
            hashedLeaves=hash.digest('hex')
            // console.log("hashedLeaves " + hashedLeaves)
            break;
        case "sha3-512":
            // console.log("sha3-512 function HLeaves")
            hash= createHash(config.merkleTree.HLeaves);
            // console.log("hash " + hash)
            hash.update(node+key)
            hashedLeaves=hash.digest('hex')
            // console.log("hashedLeaves " + hashedLeaves)
            break;
    }
     // const hash = createHash(config.merkleTree.HLeaves); -- NEW
    // const hashedLeaves = keccak256(Buffer.from(node+key))
    // const hashedLeaves = keccak256(Buffer.from(node+key))

    // const hash = await crypto.createHmac(config.merkleTree.HLeaves, key);
    // hash.update(node) -- NEW
    // let hashedLeaves = hash.digest('hex') -- NEW
    // console.log("solo chiave")
    // console.log(hashedLeaves.toString())

    // console.log("New changed: " );
    // console.log(hashedLeaves)
    return {hashedLeaves:hashedLeaves, key:key} //concateno un nonce generato random alla fine della foglia
}

export const CryptoSHATree =(node) => {

    let hashedValue,hash=null
    switch (config.merkleTree.HTree){
        case "keccak256":
            // console.log("keccak function HTREE:" )
            hashedValue= createKeccakHash(config.merkleTree.HTree).update(node).digest('hex')
            // console.log(hashedValue);
            break;
        case "sha3-256":
             // console.log("sha3-256 function HTREE")
            hash = createHash(config.merkleTree.HTree);
            hash.update(node)
            hashedValue=hash.digest('hex')
            break;
        case "sha3-512":
            // console.log("sha3-512 function HTREE")
            hash = createHash(config.merkleTree.HTree);
            hash.update(node)
            hashedValue=hash.digest('hex')
            break;
    }

    return hashedValue
}


export const createMerkleTree = async (listCred) => {
    // console.log("cred");
    // console.log(listCred);
    let obj ={}
    var nonce = {}
    var leaves = [] // lista dei nodi foglia hashati con nonce
        for(let i=0;i<listCred.length;i++){ // applico l'hash ai nodi foglia e creo una nuova chiave per ogni nodo foglia
            // console.log("sono la foglia: " + listCred[i])
           obj=await CryptoSHALeaves(listCred[i],undefined);
             // console.log("chiave + nonce")
             // console.log(obj.hashedLeaves)
            leaves.push(obj.hashedLeaves)
            let name =listCred[i].split(':',1).pop();
            nonce[name]=obj.key
            //console.log(listCred[i])
            //console.log(obj)
        }

        const tree = new MerkleTree(leaves, CryptoSHATree) // creo un MerkleTree e applico ricorsivamente l'hashing
        const nodesProof ={}; // oggetto contenente la lista dei nodi per la proof
        const root = tree.getHexRoot() // ricavo la root del MerkleTree

    for(let i=0;i<leaves.length;i++){ // aggiungo ad ogni nodo interessato, tutti i nodi che servono per l'hashing, quindi per risalire al nodo root
            // const elem= tree.getHexProof(leaves[i])
        // const elem = tree.getPositionalHexProof(leaves[i]) // elem sarà fatto così  [ [ 1,'0x547b86cd4bae2bc561dd8ff12ab62d22388aa5beef7f6aab1f4d9d21a8d11902'] , ... ] la coppia indica livello del nodo e nodo stesso
        const elem = tree.getProof(leaves[i])

        var name =listCred[i].split(':',1).pop(); // recupero la chiave dell'attributo
            nodesProof[name]=elem // Nella lista inserisco la chiave dell'attributo + lista dei nodi proof per il nodo leaves[i]
        
        }
    return {proof: nodesProof, rootTree: root, nonceLeaves: nonce}; // la creazione della VC restituisce la root + la lista della proof per la verifica di un nodo
}

