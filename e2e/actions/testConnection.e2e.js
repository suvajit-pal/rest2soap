/*  */

const { Config } = require('@adobe/aio-sdk').Core
const fs = require.requireActual('fs')
const fetch = require('node-fetch')

const namespace = Config.get('runtime.namespace')
const hostname = Config.get('cna.hostname') || 'adobeio-static.net'
const packagejson = JSON.parse(fs.readFileSync('package.json').toString())
const runtimePackage = `${packagejson.name}-${packagejson.version}`

const actionUrl = `https://${namespace}.${hostname}/api/v1/web/${runtimePackage}/testConnection`

test('returns 200 for generic fetch which does not require companyId. apiKey and token', async () => {
  const res = await fetch(actionUrl)
  expect(res).toEqual(expect.objectContaining({
    status: 200
  }))
})
