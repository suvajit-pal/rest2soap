/*
 * 	REST to SOAP Wrapper.
 *	Invokes the SOAP API endpoint.
 *
 * 	Suvajit@Adobe.
 */

const Utils = require('../utils');

async function main (params) {
			
  try {
	const util = new Utils(params);	
	let decryptedData={};

	// Check if the request is encrypted or plain text.
	if (params.encryptRequest && params.encryptRequest == 'Y') {
		await util.initPGPKeys();	
		const data = util.getPayloadData();		
		decryptedData = JSON.parse(await util.decryptData(data));				
	}
	else {
		decryptedData = JSON.parse(util.getPayloadData());
	}
			
	// Make the Campaign SOAP call.
	const restResponse = await util.makeSoapCall(decryptedData);
	
	if (params.encryptResponse && params.encryptResponse == 'Y') {

		const encryptedData = await util.encryptData(JSON.stringify(restResponse));
	
		return {
		  statusCode: 200,
		  body: encryptedData
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
      body: { error: error.message, code: error.code }
    }
  }
}

exports.main = main
