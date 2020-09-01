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

const { Config } = require('@adobe/aio-sdk').Core;
const openwhisk = require("openwhisk");

async function main(params) {
  try {
    const actionPath = (params.actionName || '').split('/');
    const action = actionPath[actionPath.length -1 ];
    if (!params.actionName || action == '' || !params.__asyncAuth || !params.__ow_headers['x-require-whisk-auth'] || params.__ow_headers['x-require-whisk-auth'] != params.__asyncAuth[action]) {
       throw new Error('Invalid request or missing auth params');
    }
    
    const apiHost = Config.get('runtime.apihost') || params.__host || ''; 
    const apiKey = Config.get('runtime.auth') || params.__auth || '';

    const ow = openwhisk({apihost: apiHost, api_key: apiKey});
    //console.log("apihost: " + apiHost + ", ow: " + ow);
    const response = await ow.actions.invoke({
      name: params.actionName, 
      blocking: false, 
      result: false,
      params: params
    });
      
    return {
      statusCode: 200,
      body: response
    }
  } catch (error) {
    console.log(error.stack);
    return {
      statusCode: 500,
      body: { error: error.message, code: error.code}
    }
  }  
}

exports.main = main