const https = require('https')
const crypto = require('crypto')
const axios = require('axios')
const urlencoded = require('form-urlencoded')

class PSD2Client {
    constructor(signingCertificate, signingKey, options) {
        const opts = typeof(options) === 'object' && options != null ? options : { } 
        
        let sslAgent = undefined 
        try {
            let signingCertificateBuffer = null
            if (Buffer.isBuffer(signingCertificate)) {
                signingCertificateBuffer = signingCertificate
            }
            if (typeof(signingCertificate) === 'string') {
                signingCertificateBuffer = Buffer.from(signingCertificate, 'hex')
            }
            if (signingCertificateBuffer === null) {
                throw new Error(`Unable to read signing certificate buffer.`)
            }
            
            let signingKeyBuffer = null
            if (Buffer.isBuffer(signingKey)) {
                signingKeyBuffer = signingKey
            }
            if (typeof(signingKey) === 'string') {
                signingKeyBuffer = Buffer.from(signingKey, 'hex')
            }
            if (signingKeyBuffer === null) {
                throw new Error(`Unable to read signing key buffer.`)
            }

            const signingX509 = new crypto.X509Certificate(signingCertificateBuffer)
            const signingPriv = crypto.createPrivateKey(signingKeyBuffer)
            if (signingX509.checkPrivateKey(signingPriv) === true) {
                this._identifier = `SN=${signingX509.serialNumber},CA=${signingX509.issuer.split('\n').join(',')}`
                this._certificate = signingX509.raw.toString('base64')
                this._key = signingPriv
            } else {
                throw new Error(`Signing key doesn't match signing certificate.`)
            }

            if (opts.sslCertificate && opts.sslKey) {
                let sslCertificateBuffer = null
                if (Buffer.isBuffer(opts.sslCertificate)) {
                    sslCertificateBuffer = opts.sslCertificate
                }
                if (typeof(opts.sslCertificate) === 'string') {
                    sslCertificateBuffer = Buffer.from(opts.sslCertificate, 'hex')
                }
                if (sslCertificateBuffer === null) {
                    throw new Error(`Unable to read authentication certificate buffer.`)
                }

                let sslKeyBuffer = null
                if (Buffer.isBuffer(opts.sslKey)) {
                    sslKeyBuffer = opts.sslKey
                }
                if (typeof(opts.sslKey) === 'string') {
                    sslKeyBuffer = Buffer.from(opts.sslKey, 'hex')
                }
                if (sslKeyBuffer === null) {
                    throw new Error(`Unable to read authentication key buffer.`)
                }

                const sslX509 = new crypto.X509Certificate(sslCertificateBuffer)
                const sslPriv = crypto.createPrivateKey(sslKeyBuffer)
                if (sslX509.checkPrivateKey(sslPriv) === true) {
                    sslAgent = new https.Agent({
                        cert: sslCertificateBuffer,
                        key: sslKeyBuffer
                    }) 
                } else {
                    throw new Error(`SSL key doesn't match SSL certificate.`)
                }
            } else {
                if (opts.sslCertificate) {
                    throw new Error('SSL key not provided!')
                } 
            }
        } catch (error) {
            let message = `Message: 'unknown'`
            try { message = typeof(error.message) === 'string' ? `Message: '${error.message}'` : `Message: 'unknown'` }
            catch { }

            throw new Error(`Unable to verify certificates. ${ message }`)
        }
        
        try {
            let axiosOpts = {
                timeout: typeof(opts.timeout) === 'number' ? opts.timeout : 16000, 
                validateStatus: () => true
            }

            if (sslAgent) {
                axiosOpts['httpsAgent'] = sslAgent
            }

            this._axios = axios.create(axiosOpts)
        } catch (error) {
            let message = `Message: 'unknown'`
            try { message = typeof(error.message) === 'string' ? `Message: '${error.message}'` : `Message: 'unknown'` }
            catch { }

            throw new Error(`Unable to create axios remote client. ${ message }`)
        }
    }

    _signedRequest(headers, body) {
        const FORBIDDEN_HEADERS = [
            'digest',
            'x-request-id',
            'tpp-signature-certificate',
            'signature'
        ]
        const SIGNED_HEADERS = [
            'digest',
            'x-request-id',
            'psu-id',
            'psu-corporate-id',
            'tpp-redirect-uri'
        ]

        let httpHeaders = typeof(headers) === 'object' ? headers : { }
        let httpBody = Buffer.isBuffer(body) ? body : null

        let headersResult = { }
        let bodyResult = Buffer.isBuffer(httpBody) ? httpBody : null

        // We have to sanitize the headers parameter. We
        // should only accept haders with value type string
        // or number. And remove headers used for signature.
        let headersKeys = Object.keys(httpHeaders)
            .filter(key => typeof(key) === 'string')
            .filter(key => typeof(httpHeaders[key]) === 'string' || typeof(httpHeaders[key]) === 'number' || typeof(httpHeaders[key]) === 'boolean')
            .filter(key => FORBIDDEN_HEADERS.includes(key.toLowerCase()) === false)

        headersKeys.forEach(key => headersResult[key] = httpHeaders[key])

        // We should add a random generated request
        // identifier. 
        let reqid = crypto.randomUUID()

        headersKeys.push('X-Request-Id')
        headersResult['X-Request-Id'] = reqid

        // Compute body hash. We are using SHA-256, but
        // we should implement SHA-512 algorithm too. 
        // TODO: Implement SHA-512 hashing method.
        let bodyHashCrypto = crypto.createHash('sha256')
        bodyHashCrypto.update(httpBody ? httpBody : Buffer.from('', 'hex'))
        let bodyHash = bodyHashCrypto.digest('base64')

        headersKeys.push('Digest')
        headersResult['Digest'] = `SHA-256=${bodyHash}`

        // Compute request signature. We will sign the
        // request with RSA-SHA256. Currently no more algorithms
        // are supported by EU.
        let headersToSign = headersKeys.filter(key => SIGNED_HEADERS.includes(key.toLowerCase()))
        let headersSignatureString = headersToSign.map(key => `${key.toLowerCase()}: ${headersResult[key]}`)
            .sort()
            .join('\n')
        let headersSignatureCrypto = crypto.createSign('RSA-SHA256')
        headersSignatureCrypto.update(headersSignatureString)
        let headersSignature = headersSignatureCrypto.sign(this._key, 'base64')

        headersResult['TPP-Signature-Certificate'] = this._certificate
        headersResult['Signature'] = `keyId="${this._identifier}",algorithm="sha-256",headers="${headersToSign.sort().join(' ').toLowerCase()}",signature="${headersSignature}"`

        return { request: reqid, headers: headersResult, body: bodyResult }
    }

    async send(method, path, headers, body, encoding) {
        const AVAILABLE_METHODS = [
            'get', 'post', 'put', 'delete'
        ]

        if (typeof(method) !== 'string') throw new Error(`Unable to send request. Message: 'invalid method type'`)
        if (AVAILABLE_METHODS.includes(method.toLowerCase()) === false) throw new Error(`Unable to send request. Message: 'invalid method'`)
        if (typeof(path) !== 'string') throw new Error(`Unable to send request. Message: 'invalid path'`)
        
        let sanitizedHeaders = typeof(headers) === 'object' ? headers : { }
        let sanitizedBody = null
        if (body) {
            try {
                if (Buffer.isBuffer(body)) {
                    sanitizedHeaders['Content-Type'] = typeof(sanitizedHeaders['Content-Type']) === 'string' ? sanitizedHeaders['Content-Type'] : 'application/octet-stream'
                    sanitizedBody = body 
                } else {
                    if (encoding === 'json' || encoding === undefined) {
                        let serializedBody = JSON.stringify(body)
                        let bufferedBody = Buffer.from(serializedBody, 'utf-8')
        
                        sanitizedHeaders['Content-Type'] = 'application/json'
                        sanitizedBody = bufferedBody
                    } else if (encoding === 'urlencoded') { 
                        let serializedBody = urlencoded(body)
                        let bufferedBody = Buffer.from(serializedBody, 'utf-8')

                        sanitizedHeaders['Content-Type'] = 'x-www-form-urlencoded'
                        sanitizedBody = bufferedBody
                    } else {
                        throw new Error(`Invalid provided encoding (${encoding}).`)
                    }
                }
            } catch (error) {
                let message = `Message: 'unknown'`
                try { message = typeof(error.message) === 'string' ? `Message: '${error.message}'` : `Message: 'unknown'` }
                catch { }
    
                throw new Error(`Unable to serialize request. ${ message }`)
            }
        }

        try {
            let signedRequest = this._signedRequest(sanitizedHeaders, sanitizedBody)

            let result = await this._axios.request({
                method: method,
                url: path,
                headers: signedRequest.headers,
                data: signedRequest.body
            })

            return { request: signedRequest.request, status: result.status, headers: result.headers, body: result.data }
        } catch (error) {
            let message = `Message: 'unknown'`
            try { message = typeof(error.message) === 'string' ? `Message: '${error.message}'` : `Message: 'unknown'` }
            catch { }

            throw new Error(`Unable to send request. ${ message }`)
        }
    }
}

module.exports = PSD2Client
