/*  REST to SOAP Wrapper.*/


const { Core } = require('@adobe/aio-sdk')
const fetch = require('node-fetch')
const openpgp = require('@tripod/openpgp'); 
const Utils = require('../utils');


async function main (params) {
			
  try {
	const util = new Utils(params);	
	const {privateKeyArmored, publicKeyArmored, secret} = util.getPGPKeys(); 		
			
	if (params.decrypted && (!privateKeyArmored || !publicKeyArmored || !secret)) {
		return {
			'Content-Type': 'application/json',
			statusCode: 400,
			body: {
				error: 'Missing one or more required configurations for encryption.'
			}				
		}		
	}
			
	const { keys: [privateKey] } = await openpgp.key.readArmored(privateKeyArmored);
	await privateKey.decrypt(secret);
	
	let decryptedData={};
	
	if (params.decrypted && params.decrypted == 'Y') {
		decryptedData = JSON.parse(util.getPayloadData());
	}
	else {
		const data = util.getPayloadData();
		
		const { data: decrypted, signatures: checkSig } = await openpgp.decrypt({
			message: await openpgp.message.readArmored(data),            		// parse armored message
			publicKeys: (await openpgp.key.readArmored(publicKeyArmored)).keys,	// for checking signature
			privateKeys: [privateKey]                                          	// for decryption
		});
		
		if (params.verifySignature && params.verifySignature == 'Y' && !checkSig[0].valid) {
			return {
				'Content-Type': 'application/json',
				statusCode: 400,
				body: {
					error: 'Request payload was malformed.'
				}				
			}
		}
		decryptedData = JSON.parse(decrypted);
	}
	const apiEndpoint = 'https://'+params.instance+'.campaign.adobe.com/nl/jsp/soaprouter.jsp';
	 
	if (!decryptedData.payload || !decryptedData.method || !decryptedData.schema || decryptedData.securityToken === undefined || decryptedData.sessionToken === undefined) {
		return {
		  'Content-Type': 'application/json',
		  statusCode: 400,
		  body: {
			error: 'Missing one or more required params sessionToken, securityToken, payload, method, schema'
		  }
		}
	}	
	
	const obj = decryptedData.payload;
	const soapRequest = util.makeSoapObj(decryptedData);
	let headers = {
					'Content-Type': 'text/xml;charset=UTF-8',
					'SOAPAction': decryptedData.schema+'#'+decryptedData.method
				  };
				  
	if 	(decryptedData.securityToken && decryptedData.securityToken != "")
		headers['X-Security-Token'] = decryptedData.securityToken;	
	if 	(decryptedData.sessionToken && decryptedData.sessionToken != "")
		headers['cookie'] = '__sessiontoken='+decryptedData.sessionToken;	
	
	const options = {
      headers: headers,
      method: 'POST',
      body: soapRequest.toString()
    };
		
	const soapResponse = await fetch(apiEndpoint, options);
    
	if (!soapResponse.ok) {
      throw new Error(`request to '${apiEndpoint}' failed with status code '${soapResponse.status}'`)
    }
	
    const content = await soapResponse.text();
	const restResponse = util.getRestResponse(content, decryptedData.method);
	
	if (params.encryptResponse && params.encryptResponse == 'Y') {
  	
		openpgp.config.compression = openpgp.enums.compression.zip;
		openpgp.config.prefer_hash_algorithm = openpgp.enums.hash.sha256;		
		openpgp.config.encryption_cipher = openpgp.enums.symmetric.aes256;
		openpgp.config.show_comment = false;
		
		const { data: encrypted} = await openpgp.encrypt({
			message: await openpgp.message.fromText(JSON.stringify(restResponse)),   // parse decrypted message
			publicKeys: (await openpgp.key.readArmored(publicKeyArmored)).keys,		// for encrypting the message
			privateKeys: [privateKey],
			armor: true,
			detached: false
		});	
		return {
		  statusCode: 200,
		  body: encrypted
		}		
	}
	else {
		return {
		  statusCode: 200,
		  body: restResponse
		}
	}
  } catch (error) {
    return {
      statusCode: 500,
      body: { error: error.toString() }
    }
  }
}

exports.main = main
