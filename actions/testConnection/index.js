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
 * Test connection 
 *	Validate Encryption Keys.
 * 	Validate Decryption Keys.
 */

const Utils = require('../utils');
	
async function main (params) {
  const util = new Utils(params);
  
  try {
	
	// if PGP encryption or decryption check is set to Y,
	// initilaize the PGP parameters
	if (params.checkDecryption && params.checkDecryption == 'Y' || params.checkEncryption && params.checkEncryption == 'Y') {
		await util.initPGPKeys();		
	}
	
	if (params.checkDecryption && params.checkDecryption == 'Y') {
		const data = util.getPayloadData();		
		
		if (!data) {
			return {
				'Content-Type': 'application/json',
				statusCode: 500,
				body: {
					error: 'Missing encrypted payload data.'
				}
			}		
		}		

		const decryptedData = await util.decryptData(data);
			
		return {
			statusCode: 200,
			body: decryptedData
		}

	}
	else if (params.checkEncryption && params.checkEncryption == 'Y') {
		const returnMsg = {message: "This is a test message from Adobe @ " + new Date()};
		
		const encryptedData = await util.encryptData(returnMsg);		
		
		return {
		  'Content-Type': 'text/plain',
		  statusCode: 200,
		  body: encryptedData
		}	
	}
	else {
		return {
		  statusCode: 200,
		  body: {response: 'Test Connection successful.'}
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
