import {Resolver} from 'did-resolver'
import getResolver from 'ethr-did-resolver'
import { EthrDID } from 'ethr-did'
import { ethers } from 'ethers' 
import { computePublicKey } from '@ethersproject/signing-key'
//import { ES256KSigner } from 'did-jwt'
// import pkg, { verifyCredential, normalizeCredential, validateCredentialPayload } from 'did-jwt-vc';
// const { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyPresentation } = pkg;
import { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyPresentation,  verifyCredential, normalizeCredential, validateCredentialPayload } from 'did-jwt-vc';
import bip39 from 'bip39'
import { createRequire } from 'module';
import { exit } from 'process'


const require = createRequire(import.meta.url);
var config =require('../config.json');
const hdkey = require('ethereumjs-wallet/hdkey')
const fs = require('fs')

const didJWT = require('did-jwt');
const Web3 = require("web3")
//import wallet from 'ethereumjs-wallet'

const { performance } = require('perf_hooks'); // performance suite for time measurement

const mnemonic = 'family dress industry stage bike shrimp replace design author amateur reopen script';

// Functionalities for BBS+
const generateBls12381G2KeyPair = require("@mattrglobal/bbs-signatures").generateBls12381G2KeyPair
const blsSign = require("@mattrglobal/bbs-signatures").blsSign
const blsVerify = require("@mattrglobal/bbs-signatures").blsVerify
const blsCreateProof = require("@mattrglobal/bbs-signatures").blsCreateProof
const blsVerifyProof = require("@mattrglobal/bbs-signatures").blsVerifyProof

// Test VCs and VPs
const vc = {
    "vc" : {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        "type": ['VerifiableCredential'],
        "credentialSubject": {}
    }
}

const vp = {
    "vp" : {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        "type": ['VerifiablePresentation'],
        "verifiableCredential": [],
        "attributes": []
    }
}

const options = {		
    header: {
        "typ": "JWT",
        "alg": "ES256K"
    },
};


console.log('Connecting to provider...');

// Web3 configuration for the registry
const web3_url =  'http://localhost:9545';
const chain_id = "0x539";
const Web3HttpProvider = require('web3-providers-http');
const web3provider = new Web3HttpProvider(web3_url);
const provider = new ethers.providers.Web3Provider(web3provider);
const web3 = new Web3(new Web3.providers.HttpProvider(web3_url));

console.log('Connected to the provider');

// Deploy registry contract
const accounts = await web3.eth.getAccounts();
const registry_compiled = JSON.parse(fs.readFileSync("./node_modules/ethr-did-registry/artifacts/contracts/EthereumDIDRegistry.sol/EthereumDIDRegistry.json"))
const c = new web3.eth.Contract(registry_compiled.abi);
const registry = await c.deploy({data: registry_compiled.bytecode}).send({from: accounts[0], gas: 10000000})
const RegAddress = registry._address;


//function where the creation of an identity will be tested
const test = async (accounts) => {

    const powers = config.bbs.powers
    const iterations = config.bbs.iterations
    const threshold = config.bbs.threshold

    const blskeypair_uni = await generateBls12381G2KeyPair(Uint8Array.from(Buffer.from(mnemonic, "utf-8")));
	const uni = await createDid(RegAddress, accounts[0], 0);

    const PaoloMori = await createDid(RegAddress, accounts[1], 1);

    const didResolver = new Resolver(getResolver.getResolver({
        rpcUrl: web3_url,
        registry: RegAddress,
        chainId: chain_id,
        provider
    }));


	// Create VC issued by university to Paolo Mori
    let n_claims = [];
    let n_vc_verification_time = [];
    let n_vc_creation_time = [];
    let n_vc_jwt_size = [];

    let n_vp_creation_time = [];
    let n_vp_verification_time = [];
    let n_vp_jwt_size = [];

    for (let i = 1; i <= powers; i++) {

        let vc_creation_time = 0;
        let vc_verification_time = 0;
        let vc_jwt_size = 0;

        let vp_creation_time = 0;
        let vp_verification_time = 0;
        let vp_jwt_size = 0;

        let start = 0;
        let end = 0;

        const pow = Math.pow(2, i);
		n_claims.push(pow);

        console.log("Working with " + pow + " claims")

        for (let j = 0; j < iterations; j++) {

            //
            // ISSUE VC
            // 
			start = performance.now();

            let claims = [];
            let credential = vc;

            // Create array of messages as requested by the bbs+ library
            // These are the messages to selectively disclose
            for (let c = 0; c < pow; c++)
                claims.push(Uint8Array.from(Buffer.from("attrName" + c + ":attrValue" + c, "utf-8")));

            const bbs_signature = await blsSign({
                keyPair: blskeypair_uni,
                messages: claims
            });
            
            credential["vc"]["credentialSubject"]["bbsPublicKey"] = blskeypair_uni.publicKey;
            credential["vc"]["credentialSubject"]["bbsSignature"] = bbs_signature;

            const vc_jwt = await createVerifiableCredentialJwt(credential, uni, options);
			
            end = performance.now();
			
            vc_creation_time += (end - start);
            vc_jwt_size += memorySizeOf(vc_jwt);

            // //
            // // VERIFY VC
            // //
            start = performance.now();
            await verifyCredential(vc_jwt, didResolver);
            end = performance.now();
            vc_verification_time += (end - start);

            //
            // ISSUE VP
            // 
            start = performance.now();

            let disclosed_claims = []   // The sub-array of claims to disclose
            let disclosed_idx = []      // The array of the indeces of the claims to disclose
            let presentation = vp
            const bbs_nonce = Uint8Array.from(Buffer.from("nonce", "utf-8"));

            for (let c = 0; c < Math.floor(pow*threshold); c++) {
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

            presentation["vp"]["attributes"] = disclosed_claims;
            presentation["vp"]["verifiableCredential"].push(vc_jwt);
            presentation["vp"]["bbsProof"] = bbs_proof;
            presentation["vp"]["bbsNonce"] = bbs_nonce;

            const vp_jwt = await createVerifiablePresentationJwt(presentation, PaoloMori, options);

            end = performance.now();

            vp_creation_time += (end - start);
            vp_jwt_size += memorySizeOf(vp_jwt);

            //
            // VERIFY VP
            //
            start = performance.now();

            // the bbs+ library works with Uint8Array
            // The did-jwt-vc library modifies such arrays into javascript objects with keys being increasing ids and values the Uint8Array elements
            // Therefore I  take the values of such objects and create the Uint8Array list back
            // The disclosed claims is a list of such objects, therefore I need to iterate it
            const received_presentation = await verifyPresentation(vp_jwt, didResolver);
            const received_bbs_proof = Uint8Array.from(Object.values(received_presentation.verifiablePresentation.vp.bbsProof));
            const received_nonce = Uint8Array.from(Object.values(received_presentation.verifiablePresentation.vp.bbsNonce));
            const vp_claims = received_presentation.verifiablePresentation.vp.attributes;
            let received_claims = [];
            for(let claim of vp_claims) {
                received_claims.push(Uint8Array.from(Object.values(claim)))
            }

            const received_credential = received_presentation.verifiablePresentation.verifiableCredential[0];
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
                exit(0)
            }

            end = performance.now();

            vp_verification_time += (end - start);
            
  		}
    
        n_vc_creation_time.push(vc_creation_time / iterations);
        n_vc_verification_time.push(vc_verification_time / iterations);
        n_vc_jwt_size.push(vc_jwt_size / iterations);
        
        n_vp_creation_time.push(vp_creation_time / iterations);
        n_vp_verification_time.push(vp_verification_time / iterations);
        n_vp_jwt_size.push(vp_jwt_size / iterations);

        console.log(`${pow} claims: DONE`)
  	}

    const vc_creation_file = fs.createWriteStream('issueBBS+VC_ES256K.txt');
    const vc_verification_file = fs.createWriteStream('verifyBBS+VC_ES256K.txt');
    const vc_size_file = fs.createWriteStream('sizeBBS+VC_ES256K.txt');
    
    const vp_creation_file = fs.createWriteStream('issueBBS+VP_ES256K.txt');
    const vp_verification_file = fs.createWriteStream('verifyBBS+VP_ES256K.txt');
    const vp_size_file = fs.createWriteStream('sizeBBS+VP_ES256K.txt');

    for(let i in n_claims) {

        vc_creation_file.write(`${n_claims[i]} ${n_vc_creation_time[i]}\n`);
        vc_verification_file.write(`${n_claims[i]} ${n_vc_verification_time[i]}\n`);
        vc_size_file.write(`${n_claims[i]} ${n_vc_jwt_size[i]}\n`);

        vp_creation_file.write(`${n_claims[i]} ${n_vp_creation_time[i]}\n`);
        vp_verification_file.write(`${n_claims[i]} ${n_vp_verification_time[i]}\n`);
        vp_size_file.write(`${n_claims[i]} ${n_vp_jwt_size[i]}\n`);

    }

    vc_creation_file.end();
    vc_verification_file.end();
    vc_size_file.end();
    vp_creation_file.end();
    vp_verification_file.end();
    vp_size_file.end();
}

// ENTRY POINT

//actual function that starts executing and this will invoke all the other pieces of code
provider.listAccounts().then((accounts) => {
	test(accounts).catch(error => console.log(error));
	//getTrufflePrivateKey(mnemonic,0).then(res => console.log(res.toString('hex')));
});


// HELPERS

//function that retrieves private keys of Truffle accounts
// return value : Promise
const getTrufflePrivateKey = (mnemonic, index) => {
	if (index < 0 || index > 9) throw new Error('please provide correct truffle account index')
	return bip39.mnemonicToSeed(mnemonic).then(seed => {
		const hdk = hdkey.fromMasterSeed(seed);
		const addr_node = hdk.derivePath(`m/44'/60'/0'/0/${index}`); //m/44'/60'/0'/0/0 is derivation path for the first account. m/44'/60'/0'/0/1 is the derivation path for the second account and so on
		//const addr = addr_node.getWallet().getAddressString(); //check that this is the same with the address that ganache list for the first account to make sure the derivation is correct
		const privKey = addr_node.getWallet().getPrivateKey();
		return privKey;
	}).catch(error => console.log('getTrufflePrivateKey ERROR : ' + error));
}


//function to create and return the object used to manage a DID
const createDid = async (RegAddress, accountAddress, index, chainId = chain_id) => {
	return getTrufflePrivateKey(mnemonic, index)
		.then(privateKey => {
			const publicKey = computePublicKey(privateKey, true);
			const uncompressedPublicKey = computePublicKey(privateKey, false);
			console.log(publicKey);
			console.log(uncompressedPublicKey);
			console.log(privateKey);
			const identifier = `did:ethr:${chainId}:${publicKey}`;
			const signer = provider.getSigner(index);
			//const signJ=didJWT.SimpleSigner(privateKey);
		   //const signJ=didJWT.EllipticSigner(privateKey);
		  
		   //const signJ=didJWT.EdDSASigner(privateKey);
		   const signJ=didJWT.ES256KSigner(privateKey,false);
			const conf = {
				//txSigner: signer,
				//privateKey : privateKey,
				signer: signJ,
				identifier: identifier,
				registry: RegAddress,
				chainNameOrId: chainId,
				provider
			};
			return new EthrDID(conf);
		})
}

function memorySizeOf(obj) {
    var bytes = 0;

    function sizeOf(obj) {
        if(obj !== null && obj !== undefined) {
            switch(typeof obj) {
            case 'number':
                bytes += 8;
                break;
            case 'string':
                bytes += obj.length * 2;
                break;
            case 'boolean':
                bytes += 4;
                break;
            case 'object':
                var objClass = Object.prototype.toString.call(obj).slice(8, -1);
                if(objClass === 'Object' || objClass === 'Array') {
                    for(var key in obj) {
                        if(!obj.hasOwnProperty(key)) continue;
                        sizeOf(obj[key]);
                    }
                } else bytes += obj.toString().length * 2;
                break;
            }
        }
        return bytes;
    };

    function formatByteSize(bytes) {
        if(bytes < 1024) return bytes + " bytes";
        else if(bytes < 1048576) return(bytes / 1024).toFixed(3) + " KiB";
        else if(bytes < 1073741824) return(bytes / 1048576).toFixed(3) + " MiB";
        else return(bytes / 1073741824).toFixed(3) + " GiB";
    };

    return sizeOf(obj);
};
