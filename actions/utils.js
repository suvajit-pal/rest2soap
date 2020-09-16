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
* Generic Utility Methods
* This file exposes some common utilities for our actions. 
*/

const { Config } = require('@adobe/aio-sdk').Core;
const { create, fragment, convert } = require('xmlbuilder2');
const fetch = require('node-fetch');
const openpgp = require('@tripod/openpgp'); 

/**
 * 
 * @param {object} Input params object to our actions
 * Constructor function. 
 */
function Utils(params) { 
	this.__params = params; 
	
	this.__soapConfig = require('./accSoapConfig');	
	this.__mobileConfig = require('./aioMobileConfig');
}

Utils.__isLock = false;

/**
 * Initializes the persistent State library
 */
Utils.prototype.initState = async function() {
	if (this.__state && this.__state != null) return this.__state;
	//return null;
	const namespace = Config.get('runtime.namespace') || this.__params.__namespace || ''; 
	const auth = Config.get('runtime.auth') ||  this.__params.__auth || ''; 

	if (namespace != '' && namespace != 'guest' && auth != '') {
		const stateLib = require('@adobe/aio-lib-state');
		const state = await stateLib.init({ow: {namespace: namespace, auth: auth}});
		this.__state = state;
		return this.__state;
	}
	else return null;
}	

/**
 * Returns a cleaned json structure for SOAP requests
 * @param {object} object to clean / sanitize.
 *
 * @returns {object} cleaned object
 */
Utils.prototype.cleanPropnames = function(obj) {
    for (var property in obj) {
        if (property === '!') delete obj[property];
		
		if (obj.hasOwnProperty(property)) {
			var newPropname;
			if (property.indexOf(this.__soapConfig.urnKeyword) >= 0) {
				newPropname = property.replace(this.__soapConfig.urnKeyword,'');
				obj[newPropname] = obj[property];
				delete obj[property];
			}
			else 
				newPropname = property;
			
            if (typeof obj[newPropname] == "object")
                obj[newPropname] = this.cleanPropnames(obj[newPropname]);
        }
    }
	return obj;	
}

/**
 * Set's the preferences of openpgp encryption
 * @param {object} openpgp object
 *
 * @returns {object} openpgp object
 */
Utils.prototype.setPGPPreferences = function(openpgp) {
	openpgp.config.compression = openpgp.enums.compression.zip;
	openpgp.config.prefer_hash_algorithm = openpgp.enums.hash.sha256;		
	openpgp.config.encryption_cipher = openpgp.enums.symmetric.aes256;
	openpgp.config.show_comment = false;
	
	return openpgp;
}

/**
 * Initiatlizes the PGP options 
 *
 */
Utils.prototype.initPGPKeys = async function() {

	if (!this.__privateKey && !this.__publicKey) {
		const privateKeyArmored = this.__params.private_key ? this.__params.private_key : (Buffer.from(this.__params.f_private_key, 'base64')).toString('ascii');
		const publicKeyArmored = this.__params.public_key ? this.__params.public_key : (Buffer.from(this.__params.f_public_key, 'base64')).toString('ascii');
		const pass = this.__params.pass;
		
		if (!privateKeyArmored || !publicKeyArmored || !pass) {
			throw new Error('Missing one or more required configurations for encryption.');	
		}

		this.setPGPPreferences(openpgp);
		
		const { keys: [privateKey] } = await openpgp.key.readArmored(privateKeyArmored);
		await privateKey.decrypt(pass);	
		
		const { keys: [publicKey] } = await openpgp.key.readArmored(publicKeyArmored);

		this.__privateKey = [privateKey];
		this.__publicKey = [publicKey];
	}

}

/**
 * @param {data} Armoured data to be decrypted.
 * 
 * @returns Decrypted plaintext or an exception if decryption fails
 */
Utils.prototype.decryptData = async function (data) {
	await this.initPGPKeys();

	const { data: decrypted, signatures: checkSig } = await openpgp.decrypt({
		message: await openpgp.message.readArmored(data),    // parse armored message
		publicKeys: this.__publicKey,								// for checking signature
		privateKeys: this.__privateKey                             	// for decryption
	});
	
	if (this.__params.verifySignature && this.__params.verifySignature == 'Y' && !checkSig[0].valid) {
		throw new Error('Request payload was malformed.');
	}	

	return decrypted;
}

/**
 * @param {data} Plaintext data to be encrypted
 * 
 * @returns Encrypted armoured data
 */
Utils.prototype.encryptData = async function (data) {
	await this.initPGPKeys();

	if (this.__params.verifySignature && this.__params.verifySignature == 'Y') {
		const { data: encrypted} = await openpgp.encrypt({
			message: await openpgp.message.fromText(data),  // parse decrypted message
			publicKeys: this.__publicKey,					// for encrypting the message
			privateKeys: this.__privateKey,					// for signing the message
			armor: true,
			detached: false
		});	

		return encrypted;
	}
	else {
		const { data: encrypted} = await openpgp.encrypt({
			message: await openpgp.message.fromText(data),   // parse decrypted message
			publicKeys: this.__publicKey,					// for encrypting the message
			armor: true
		});	

		return encrypted;		
	}


}

/**
 * Returns the payload data
 *
 * @returns {string} the payload data
 */
Utils.prototype.getPayloadData = function() {
	return this.__params.data ? this.__params.data : this.__params.__ow_body;
}

/**
 * Returns the payload data
 *
 * @returns {string} the soap payload data
 */
Utils.prototype.getSoapRequest = function() {
	return this.__params.soapRequest ? this.__params.soapRequest : this.__params.__ow_body;
}

/**
 * Returns the SOAP request object 
 * @param {object} input rest object
 *
 * @returns {object} The SOAP request XML
 */
Utils.prototype.makeSoapObj = function (obj) {
	
	const firstElement = Object.getOwnPropertyNames(obj.payload)[0];
	let reqElemName = firstElement;
	let fragmentPayload = {};
	
	if (typeof obj.payload[firstElement] == "object") {
		reqElemName = this.__soapConfig.urnKeyword+reqElemName;
		fragmentPayload[reqElemName] = obj.payload[Object.getOwnPropertyNames(obj.payload)[0]];
	}
	else {
		for (var prop in obj.payload) {
			fragmentPayload[prop] = obj.payload[prop];
		}
	}
	
	const frag = fragment({convert: {att: this.__soapConfig.attrPrefix}}, fragmentPayload);

	const rootObj = {};
	rootObj[this.__soapConfig.soapEnvStr] = '';

	const soapReq = create(rootObj)
					.root().att(this.__soapConfig.soapNsStr, this.__soapConfig.soapNsUrl)
					.root().att(this.__soapConfig.namespaceStr, this.__soapConfig.urnKeyword+obj.schema)
					.ele(this.__soapConfig.soapHeaderStr)
					.up().ele(this.__soapConfig.soapBodyStr)
						.ele(this.__soapConfig.urnKeyword+obj.method)
							.ele(this.__soapConfig.sessionStr)
							.up().import(frag)
							.end();			
	return soapReq;
}

/**
 * Returns the REST object 
 * @param {object} input soap object as xml
 *
 * @returns {object} REST object
 */
Utils.prototype.getRestRequestFormat = function (soapRequest) {
	
	const reqObject = convert({convert: {att: this.__soapConfig.attrPrefix}}, soapRequest, {format: 'object'});
	const schemaName = reqObject[this.__soapConfig.soapEnvStr][this.__soapConfig.attrPrefix + this.__soapConfig.namespaceStr].replace(this.__soapConfig.urnKeyword,'');
	const reqMethod = Object.getOwnPropertyNames(reqObject[this.__soapConfig.soapEnvStr][this.__soapConfig.soapBodyStr])[0].replace(this.__soapConfig.urnKeyword,'');
	
	let requestPayload = reqObject[this.__soapConfig.soapEnvStr][this.__soapConfig.soapBodyStr][this.__soapConfig.urnKeyword+reqMethod];
	delete  requestPayload[this.__soapConfig.sessionStr];
	
	let restRequestFormat = {schema: schemaName, method: reqMethod, payload: this.cleanPropnames(requestPayload)};

	// if this is an offer proposition call, add the offer environment and offer space
	if ((schemaName === this.__soapConfig.offerProposeSchema && reqMethod === this.__soapConfig.offerProposeMethod)
		|| (schemaName === this.__soapConfig.offerPropositionUpdateSchema && reqMethod === this.__soapConfig.offerPropositionUpdateMethod)) {
		
		restRequestFormat.offerEnv = '<<Pass Offer environment name>>';
		restRequestFormat.offerSpace = '<<Pass Offer space name>>';
	}
	if (!this.__params.generateToken || this.__params.generateToken === 'N') {
		restRequestFormat.securityToken = '<<Pass security token from Logon method response>>';
		restRequestFormat.sessionToken = '<<Pass session token from Logon method response>>';
	}
	return restRequestFormat;
}
	
/**
 * Returns the JSON object after sanitization 
 * @param {object} input  object
 *
 * @returns {object} object sanitized of soap attributes
 */
Utils.prototype.cleanSoapPropNames = function (obj) {
    for (var property in obj) {
		if (this.__soapConfig.filterResponseElements.find(function(keyword) { return this.lookup.indexOf(keyword) >= 0 }, {lookup: property}))
			delete obj[property];
		else {
			if (obj.hasOwnProperty(property)) {
				if (typeof obj[property] == "object"){
					obj[property] = this.cleanSoapPropNames(obj[property]);
					if (Object.getOwnPropertyNames(obj[property]).length == 0) delete obj[property];
				}
			}
			if (Array.isArray(obj[property])){
				obj[property] = obj[property].filter(function(e) {
					return e != null;
				});
				
				if (obj[property].length == 0) delete obj[property];
			}
		}
		
    }
	return obj;
}

/**
 * Returns the REST response 
 * @param {object} input soap xml
 * @param {string} the method that was invoked
 *
 * @returns {object} Response REST object sanitized of soap attributes
 */
Utils.prototype.getRestResponse = function (obj, method) {

	const response = convert({convert: {att: this.__soapConfig.attrPrefix, text: this.__soapConfig.valueKey}}, obj, {format: 'object'});
	
	let restResponse = response[this.__soapConfig.soapEnvRespStr][this.__soapConfig.soapBodyRespStr][this.__soapConfig.nsKeyword+method+'Response'];
	if (!restResponse || restResponse == undefined) {
		restResponse = response[this.__soapConfig.soapEnvRespStr][this.__soapConfig.soapBodyRespStr][this.__soapConfig.urnKeyword+method+'Response'];
		if (!restResponse || restResponse == undefined) {
			restResponse = response[this.__soapConfig.soapEnvRespStr][this.__soapConfig.soapBodyRespStr][this.__soapConfig.soapFaultRespStr];
			if (!restResponse || restResponse == undefined) throw new Error(`Failed to parse response. Original response ${JSON.stringify(response)}`);
		}
	}
	restResponse = this.cleanSoapPropNames(restResponse);
	//console.log("Returning from REST response " + JSON.stringify(restResponse));
	return restResponse;
}

/**
 * Returns the login Payload
 *
 *
 * @returns {object} the login payload
 */
Utils.prototype.getLoginPayload = function(instanceName = '') {

	const loginPayload = {
							method: "Logon",
							payload: {
								strLogin: (instanceName == '' ? this.__params.instanceLoginAPI : this.__params[instanceName].instanceLoginAPI),
								strPassword: (instanceName == '' ? this.__params.instanceLoginAPIKey : this.__params[instanceName].instanceLoginAPIKey),
								elemParameters: {}
							},
							schema: "xtk:session",
							securityToken: "",
							sessionToken: ""
						};    
	
	const soapPayload = this.makeSoapObj(loginPayload);

	const headers = {
					'Content-Type': 'text/xml;charset=UTF-8',
					'SOAPAction': loginPayload.schema+'#'+loginPayload.method
				  };
	
	const requestPayload = {
      headers: headers,
      method: 'POST',
      body: soapPayload.toString()
    };	
	
	return requestPayload;	
}

/**
 * @param {object} Input request object in JSON format.
 * @param {boolean} Force generation of token if required.
 * 
 * @returns The REST format response returned
 */
Utils.prototype.makeSoapCall = async function(requestObj, generateToken = false, instanceName = '', useTokens = false) {
	
	if (!requestObj || !requestObj.payload || !requestObj.method || !requestObj.schema ) {
		throw new Error('Missing one or more required params payload, method, schema');
	}

	/** Check if this is an offer proposition or proposition update call, then route accoridngly */
	if (requestObj && 
			(  (requestObj.schema === this.__soapConfig.offerProposeSchema && requestObj.method === this.__soapConfig.offerProposeMethod) 
			|| (requestObj.schema === this.__soapConfig.offerPropositionUpdateSchema && requestObj.method === this.__soapConfig.offerPropositionUpdateMethod))){
		
		// this is an offer proposition or offer proposition update call
		if (!requestObj.offerEnv || !requestObj.offerSpace) {
			throw new Error('Missing offerEnv or offerSpace for Offer Interaction calls');
		}

		const interactionResponse = await this.makeInteractionSoapCall(requestObj, requestObj.offerEnv, requestObj.offerSpace, this.__params.interactionServer);
		return interactionResponse;
	}
	else {
		const instance = instanceName == '' ? this.__params.instance : instanceName;
		const apiEndpoint = this.getSOAPAPIEndpoint(instance) ;
		//console.log("-- API ENDPOINT : " + apiEndpoint);
		const tokenKey = 'tokens_'+instance;
	
		// Check if we expect logon token to be available.
		if ((this.__params.generateToken && this.__params.generateToken === 'Y' && !useTokens) || generateToken) {
			// The system should automatically generate logon tokens.
			// any tokens passed in the input will be overwridden.
		
			let loginTokens = await this.getKeyValue(tokenKey);
			//console.log("-- login tokens " + JSON.stringify(loginTokens));
			if (!loginTokens) {
				console.log(' --- getting new tokens for ' + instance);
				loginTokens = await this.getTokens(instance);
				
				// save the token for reuse
				await this.setKeyValue(tokenKey, loginTokens, (loginTokens.sesstionTimeout > 3000 ? loginTokens.sesstionTimeout-3000: loginTokens.sesstionTimeout)); // reduce timeout by 3 sec for edge cases where token will expire soon.
			}	
			requestObj.securityToken = loginTokens.securityToken;
			requestObj.sessionToken = loginTokens.sessionToken;		
		}		

		if (requestObj.securityToken === undefined || requestObj.sessionToken === undefined) {
			throw new Error('Missing one or more required params sessionToken, securityToken.');
		}

		// Build the SOAP request XML from the rest object
		const soapRequest = this.makeSoapObj(requestObj);
		let headers = {
						'Content-Type': 'text/xml;charset=UTF-8',
						'SOAPAction': requestObj.schema+'#'+requestObj.method
					  };
		
		// Add authentication tokens
		if 	(requestObj.securityToken && requestObj.securityToken != "")
			headers['X-Security-Token'] = requestObj.securityToken;	
		if 	(requestObj.sessionToken && requestObj.sessionToken != "")
			headers['cookie'] = '__sessiontoken='+requestObj.sessionToken;	
		
		// Define the final payload
		const options = {
		  headers: headers,
		  method: 'POST',
		  body: soapRequest.toString()
		};
		
		// Make the soap call
		const soapResponse = await fetch(apiEndpoint, options);
		
		if (!soapResponse.ok) {
			// if the response has failed and we used auto generate tokens, 
			// reset the key as the cached tokens are most probably invalid.
			if ((this.__params.generateToken && this.__params.generateToken === 'Y') || generateToken) {
				await this.setKeyValue(tokenKey, null);
			}
			throw new Error(`request to '${apiEndpoint}' failed with status code '${soapResponse.status}'`)
		}
		
		// Retrieve the response.
		const content = await soapResponse.text();
		// Transpose it to a valid JSON object
		const restResponse = this.getRestResponse(content, requestObj.method);
	
		return restResponse;
	
	}
}

/**
 * @param {object} Input request object in JSON format.
 * @param {boolean} Force generation of token if required.
 * 
 * @returns The REST format response returned
 */
Utils.prototype.makeInteractionSoapCall = async function(requestObj, environment = '', space = '', serverName = '', serverUrl = '') {
	
	const apiEndpoint = (serverUrl != '' ? serverUrl : "https://" + (serverName != '' ? serverName : this.__params.interactionServer)+"/interaction/"+environment+"/"+space);
	// console.log('--- Final interaction endpoint: ' + apiEndpoint);
	// Build the SOAP request XML from the rest object
	const soapRequest = this.makeSoapObj(requestObj);
	//return soapRequest;
	let headers = {
					'Content-Type': 'text/xml;charset=UTF-8',
					'SOAPAction': requestObj.schema+'#'+requestObj.method
				  };
	
	// Define the final payload
	const options = {
      headers: headers,
      method: 'POST',
      body: soapRequest.toString()
	};
	
	// Make the soap call
	const soapResponse = await fetch(apiEndpoint, options);
    	
	// Retrieve the response.
	const content = await soapResponse.text();
	// Transpose it to a valid JSON object
	const restResponse = this.getRestResponse(content, requestObj.method);

	return restResponse;
}

/**
 * Performs Login and retrieves token
 *
 *
 * @returns {object} the session and security tokens
 */
Utils.prototype.getTokens = async function(instanceName = '') {

	const loginPayload = this.getLoginPayload(instanceName);
	const apiEndpoint = this.getSOAPAPIEndpoint(instanceName);
	const soapResponse = await fetch(apiEndpoint, loginPayload);
    
	if (!soapResponse.ok) {
      throw new Error(`Login request to '${apiEndpoint}' failed with status code '${soapResponse.status}'`)
    }
	
    const content = await soapResponse.text();
	const restResponse = this.getRestResponse(content, 'Logon');
	
	const securityToken = restResponse.pstrSecurityToken.value || '';
	const sessionToken = restResponse.pstrSessionToken.value || '';
	const sesstionTimeout = restResponse.pSessionInfo.sessionInfo.serverInfo.attr_sessionTimeOut;
	
	return {securityToken: securityToken, sessionToken: sessionToken, sessionTimeout: sesstionTimeout}; 
		
}

/**
 * Get the SOAP API endpoint
 *
 *
 * @returns {string} the SOAP API endpoint
 */
Utils.prototype.getSOAPAPIEndpoint = function(instanceName = '') {

	const instance = instanceName == '' ? this.__params.instance : instanceName;
	
	return this.__params[instance] && this.__params[instance]['soapEndPointUrl'] ?  this.__params[instance]['soapEndPointUrl'] : 'https://'+ instance +'-t.adobe-campaign.com/nl/jsp/soaprouter.jsp';	
}

/**
 * Returns the key value persisted or undefined
 * @param {string} key name
 *
 * @returns {any} The value associated with the key
 */

Utils.prototype.getKeyValue = async function(key) {
	
	await this.initState();	
	if (!this.__state) return null;

	const val = await this.__state.get(key);		
	if (!val) return null;
	 
	const expired = new Date(val.expiration);
	const now = new Date();
		
	if (expired <= now) return null;
	else return val.value;
}

/**
 * Sets the key value to be persisted
 * @param {string} key name
 * @param {any} associated value
 *
 * @returns {any} The value associated with the key
 */
Utils.prototype.setKeyValue = async function(key, value, duration = 86400) {

	await this.initState();	
	if (!this.__state) return null;
	
	if (key == null || key == undefined || key == '') return;
	
	await this.__state.put(key, value, {ttl: duration});
	//console.log('--- Saving state : ' + JSON.stringify({key: key, value: value, duration: duration}));
}

/**
* Sleeps for the specified milli-seconds.
* @param {integer} milliseconds to sleep
*
* @returns {none} 
*/
Utils.prototype.sleep = function(delay) {
	return new Promise(resolve => setTimeout(resolve, delay));
}

/**
* Acquire a lock based on input key.
* The lock indicator is saved via aio-lib-state
* Note - Due to multi-threaded nature, this is a best effort locking functionality 
*			and does not gaurantee a lock success means exclusive lock in all scenarios.
* @param {string} the lock key
*
* @returns {boolean} true if the lock is successfully acquired, else false. 
*/
Utils.prototype.acquireLock = async function (key) {
	const sleepTimings = [100, 300, 500, 400, 200];
	const maxIter = 1000; // max times we will iter while trying to set the lock.

	for (var i = 0; i < maxIter; i++) {
		await this.sleep(sleepTimings[Math.floor(Math.random()*sleepTimings.length)]); // randomly wait for few m-sec.

		if (!Utils.__isLock) {
			Utils.__isLock = true; // set to true

			const value = await this.getKeyValue(key);

			if (!value) {
				await this.setKeyValue(key, new Date(), 300);
				return true;
			}
			else {
				Utils.__isLock = false;
			}
		}		
	}
	return false;
}

/**
* Unlock a lock acquired via acquireLock method.
* The lock indicator is saved via aio-lib-state.
* @param {string} the lock key
*
* @returns {boolean} true
*/
Utils.prototype.unlock = async function (key) {
	await this.setKeyValue(key, new Date(), 1);
	Utils.__isLock = false;
	
	return true;
}

/**
 * Returns the formatted mobile number
 * @param {string} mobNumber the mobile number with or without country code.
 *        e.g. +886876354636 or (886)876354636 or 876354636
 * @param {string} countryCode eg, 886, +886, 91, +91, 65, +65, etc.
 *
 * @returns {string} mobile number with country code
 */

Utils.prototype.formatMobileNumber = function (mobNumber, countryCode = null) {
	const mobOptions = this.__mobileConfig.aioMobileConfig;	
	// lookup countryCode and find country
	let country = mobOptions.default_country;

	if (countryCode && (!mobOptions.asNull || mobOptions.asNull && mobOptions.asNull.indexOf(countryCode) == -1)) {
		countryCode = countryCode.replace(/[^\d]/g, ''); // remove non numeric characters
		
		for (let [key, value] of Object.entries(mobOptions)) {			
			if (value && value.code && value.code == countryCode) {
				country = key;
				break;
			}
		}		
	}
	const countryCodePrefix = mobOptions[country].code;
	const numberLength = mobOptions[country].length;

	// check if any number validator needs to be executed
	if (mobOptions[country] && mobOptions[country].numberValidator) {
		var regCheck = new RegExp(mobOptions[country].numberValidator);
		if (!regCheck.test(mobNumber)) return ''; // return empty string if number fails validation
		
		const testNumber = mobNumber.replace(regCheck, '').replace(/[^\d]/g, '');
		if (testNumber != '' && testNumber.length < numberLength) return '';
	}

	// now clean the mobile number
	const mobileNumber = mobOptions[country].asNull && mobOptions[country].asNull.indexOf(mobNumber) > -1 ? '' : mobNumber.replace(/[^\d]/g, ''); // remove non numeric characters
	if (mobileNumber.length < numberLength || Number.isNaN(Number.parseInt(mobileNumber)) || Number.parseInt(mobileNumber) == 0) return '';

	const formattedMobNumber = countryCodePrefix + mobileNumber.substr(-1*numberLength);

	return formattedMobNumber;
}

module.exports = Utils;
