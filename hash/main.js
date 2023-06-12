import {hashAttributes} from './hashAttributes.js'
import {verifyAttributes} from './verifyAttributes.js'
import { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyPresentation,  verifyCredential, normalizeCredential, validateCredentialPayload } from 'did-jwt-vc';


const options = {		
		header: {
			"typ": "JWT",
			"alg": "ES256K"
		},
	};

let disclosure=new Map();

async function createVCPayload(user,nClaims) {
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
  		const hashedAttr = await hashAttributes(attrValue,undefined,undefined,undefined);
  		disclosure.set(attrName,{path : [attrName],clearValue : attrValue,nonce : hashedAttr.nonce});
  		VCPayload['vc']['credentialSubject'][attrName] = hashedAttr.res;
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


function createVPPayload(vc,nClaims) {
	const VCPayload={};
	//VCPayload['sub']=user.did;
    //VCPayload['nbf']=626105238;
    VCPayload['vp']= {
			'@context': ['https://www.w3.org/2018/credentials/v1'],
			type: ['VerifiablePresentation'],
			verifiableCredential: [vc]
		};
	VCPayload['vp']['attributes']=[];
	if (nClaims==disclosure.size) {
		disclosure.forEach (function(value, key){
			VCPayload['vp']['attributes'].push(value);
		});	
	}else{
		let keys=Array.from(disclosure.keys());
		for (let i = 0; i < nClaims; i++) {
			let attN=keys[i];
			VCPayload['vp']['attributes'].push(disclosure.get(attN));
		}
	}
	return VCPayload;
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