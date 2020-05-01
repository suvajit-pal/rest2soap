/*
Copyright 2020 Adobe. All rights reserved.
This file is licensed to you under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License. You may obtain a copy
of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
OF ANY KIND, either express or implied. See the License for the specific language
governing permissions and limitations under the License.

Author: Suvajit@Adobe
*/
/*
 * 	REST to SOAP Wrapper.
 *	Invokes the Adobe Campaign (Classic) SOAP API endpoint.
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
