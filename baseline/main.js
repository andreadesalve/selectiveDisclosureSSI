import {Resolver} from 'did-resolver'
import getResolver from 'ethr-did-resolver'
import { EthrDID } from 'ethr-did'
import { ethers } from 'ethers' 
import { computePublicKey } from '@ethersproject/signing-key'
//import { ES256KSigner } from 'did-jwt'
// import pkg, { verifyCredential, normalizeCredential, validateCredentialPayload } from 'did-jwt-vc';
// const { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyPresentation } = pkg;
import { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyPresentation,  verifyCredential, normalizeCredential, validateCredentialPayload } from 'did-jwt-vc';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { performance } = require('perf_hooks'); // performance suite for time measurement
const didJWT = require('did-jwt');

const options = {		
		header: {
			"typ": "JWT",
			"alg": "ES256K"
		},
	};

export async function issueVC(issuer,subject,nClaims){
	let start = performance.now();
	const VCPayload = createVCPayload(subject,Math.pow(2, nClaims));
	const jwt =  await createVerifiableCredentialJwt(VCPayload, issuer, options);
	let end = performance.now();
	const time = (end-start);
  	return {jwt,time}
}

export async function verifyVC(jwt,didResolver){
	let start = performance.now();
	const verifiedCredential = await verifyCredential(jwt, didResolver,{});
	let end = performance.now();
	const time = (end-start);
	return time;
}

export async function issueVP(jwt,n,subject){
	let start = performance.now();
	const VPPayload=createVPPayload(jwt);
	const jwtVP= await createVerifiablePresentationJwt(VPPayload,subject,{});
	let end = performance.now();
	const time = (end-start);
	return {jwtVP, time};
}

export async function verifyVP(jwt,didResolver){
	let start = performance.now();
	const verifiedPresentation = await verifyPresentation(jwt, didResolver,{});
	let end = performance.now();
	const time = (end-start);
	return time;
}

function createVCPayload(user,nClaims) {
	const VCPayload={};
	//VCPayload['sub']=user.did;
    //VCPayload['nbf']=626105238;
    VCPayload['vc']= {
			'@context': ['https://www.w3.org/2018/credentials/v1'],
			type: ['VerifiableCredential'],
			credentialSubject: {}
		};
	for (let i = 0; i < nClaims; i++) {
		var attrName="attrName"+i;
		var attrValue="attrValue"+i;
  		VCPayload['vc']['credentialSubject'][attrName] = attrValue;
	} 
	return VCPayload;
}

function createVPPayload(vc) {
	const VCPayload={};
	//VCPayload['sub']=user.did;
    //VCPayload['nbf']=626105238;
    VCPayload['vp']= {
			'@context': ['https://www.w3.org/2018/credentials/v1'],
			type: ['VerifiablePresentation'],
			verifiableCredential: [vc],
		};
	return VCPayload;
}
