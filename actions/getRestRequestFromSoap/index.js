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
 * Helper action to get REST request format from a SOAP requets format.
 *
*/

const Utils = require('../utils');

async function main (params) {

  try {

	const util = new Utils(params);
	
	const soapRequest = util.getSoapRequest();
	if (!soapRequest) {
		return {
		  'Content-Type': 'application/json',
		  statusCode: 500,
		  body: {
			error: 'Missing one or more required params : soapRequest'
		  }
		}	
	}
		
	return {
      statusCode: 200,
      body: util.getRestRequestFormat(soapRequest)
    }
  } catch (error) {
    return {
      statusCode: 500,
      body: { error: error.message, code: error.code }
    }
  }
}

exports.main = main
