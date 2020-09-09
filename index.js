/*
 * @author: HellyW
 * @create_time: 2020-07-01
 * @update_time: 2020-07-03
 */


// WXBizMsgCrypt.js
// 微信加解密算法

//-40001 ： 签名验证错误
//-40002 :  xml解析失败
//-40003 :  sha加密生成签名失败
//-40004 :  AESKey 非法
//-40005 :  appid 校验错误
//-40006 :  AES 加密失败
//-40007 ： AES 解密失败
//-40008 ： 解密后得到的buffer非法
//-40009 :  base64加密异常
//-40010 :  base64解密异常

const crypto = require("crypto")
const xml2js = require('xml2js')
const Cryptography = require('./libs/Cryptography')


const xmlBuilder = new xml2js.Builder({
    headless: true,
    rootName: 'xml',
    cdata: true
})

const WXBizMsgCryptErrorCode = {
    "WXBizMsgCrypt_OK": 0,
    "WXBizMsgCrypt_ValidateSignature_Error": -40001,
    "WXBizMsgCrypt_ParseXml_Error": -40002,
    "WXBizMsgCrypt_ComputeSignature_Error": -40003,
    "WXBizMsgCrypt_IllegalAesKey": -40004,
    "WXBizMsgCrypt_ValidateAppid_Error": -40005,
    "WXBizMsgCrypt_EncryptAES_Error": -40006,
    "WXBizMsgCrypt_DecryptAES_Error": -40007,
    "WXBizMsgCrypt_IllegalBuffer": -40008,
    "WXBizMsgCrypt_EncodeBase64_Error": -40009,
    "WXBizMsgCrypt_DecodeBase64_Error": -40010,
    "WXBizMsgCrypt_VerifySignature_Error": -40011
}

const _xml2json = xmlStr => {
    return new Promise((resolve, reject) => {
        try {
            xml2js.parseString(xmlStr, {
                trim: true,
                explicitArray: false
            }, (err, xmlBody) => {
                if (err) throw err
                resolve(xmlBody.xml)
            })
        } catch (err) {
            reject(WXBizMsgCryptErrorCode.WXBizMsgCrypt_ParseXml_Error)
        }
    })
}

const _json2xml = jsonObj => {
    return new Promise((resolve, reject) => {
        try {
            resolve(xmlBuilder.buildObject(jsonObj))
        } catch (err) {
            reject(WXBizMsgCryptErrorCode.WXBizMsgCrypt_ParseXml_Error)
        }
    })
}


class WXBizMsgCrypt {
    constructor(sToken, sEncodingAESKey, sAppID) {
            this.m_sToken = sToken
            this.m_sAppID = sAppID
            this.m_sEncodingAESKey = sEncodingAESKey
            this.cryptography = new Cryptography(sEncodingAESKey)
        }
        // 检验消息的真实性，并且获取解密后的明文
        // @param sMsgSignature: 签名串，对应URL参数的msg_signature
        // @param sTimeStamp: 时间戳，对应URL参数的timestamp
        // @param sNonce: 随机串，对应URL参数的nonce
        // @param sPostData: 密文，对应POST请求的数据
        // @param type: sPostMsg的数据格式 支持json 、 xml
        // @return: 格式化的json数据
    DecryptMsg(sMsgSignature, sTimeStamp, sNonce, sPostData, type='json') {
            return new Promise(async(resolve, reject) => {
                try {
                    if (this.m_sEncodingAESKey.length !== 43) return reject(WXBizMsgCryptErrorCode.WXBizMsgCrypt_IllegalAesKey)
                    try {
                        // xml2json format
                        if(type === 'xml') sPostData = await _xml2json(sPostData)
                        const sEncryptMsg = sPostData.Encrypt
                        // 
                        try {
                            await this.VerifySignature(sTimeStamp, sNonce, sEncryptMsg, sMsgSignature)
                        } catch (err) {
                            console.log(err)
                            throw err
                        }
                        try {
                            // verify signature
                            var sMsg = await this.cryptography.AES_decrypt(sEncryptMsg, this.m_sEncodingAESKey)
                        } catch (err) {
                            throw WXBizMsgCryptErrorCode.WXBizMsgCrypt_DecodeBase64_Error
                        }
                        // xml2json format
                        const msg = await _xml2json(sMsg)
                        resolve(msg)
                    } catch (err) {
                        reject(err)
                    }
                } catch (err) {
                    reject(WXBizMsgCryptErrorCode.WXBizMsgCrypt_DecryptAES_Error)
                }
            })
        }
        //将企业号回复用户的消息加密打包
        // @param sReplyMsg: 企业号待回复用户的消息，xml格式的字符串
        // @param sTimeStamp: 时间戳，可以自己生成，也可以用URL参数的timestamp
        // @param sNonce: 随机串，可以自己生成，也可以用URL参数的nonce
        // @param sEncryptMsg: 加密后的可以直接回复用户的密文，包括msg_signature, timestamp, nonce, encrypt的xml格式的字符串,
        //            当return返回0时有效
        // return：发放状态
    EncryptMsg(sReplyMsg, sTimeStamp, sNonce) {
        return new Promise(async(resolve, reject) => {
            try {
                if (this.m_sEncodingAESKey.length !== 43) throw WXBizMsgCryptErrorCode.WXBizMsgCrypt_IllegalAesKey
                try {
                    var sEncryptMsg = await this.cryptography.AES_encrypt(sReplyMsg, this.m_sEncodingAESKey, this.m_sAppID)
                } catch (err) {
                    throw WXBizMsgCryptErrorCode.WXBizMsgCrypt_EncryptAES_Error
                }
                try {
                    var sMsgSigature = await this.GenarateSinature(sTimeStamp, sNonce, sEncryptMsg)
                } catch (err) {
                    throw err
                }
                const jsonBody = {
                    "Encrypt": sEncryptMsg,
                    "MsgSignature": sMsgSigature,
                    "TimeStamp": sTimeStamp,
                    "Nonce": sNonce
                }
                try{
                    var sEncryptMsg = await _json2xml(jsonBody)
                }catch(err){
                    throw err
                }
                resolve(sEncryptMsg)
            } catch (err) {
                reject(err)
            }
        })
    }
    VerifySignature(sTimeStamp, sNonce, sMsgEncrypt, sSigture) {
        //Verify Signature
        return new Promise(async(resolve, reject) => {
            try {
                try {
                    var hash = await this.GenarateSinature(sTimeStamp, sNonce, sMsgEncrypt)
                } catch (err) {
                    throw err
                }
                console.log(hash,sSigture)
                if (hash === sSigture) return resolve()
                throw WXBizMsgCryptErrorCode.WXBizMsgCrypt_ValidateSignature_Error
            } catch (err) {
                reject(err)
            }
        })
    }
    GenarateSinature(sTimeStamp, sNonce, sMsgEncrypt) {
        return new Promise((resolve, reject) => {
            try {
                var AL = [this.m_sToken, sTimeStamp, sNonce, sMsgEncrypt].sort()
                resolve(crypto.createHash('sha1').update(AL.join('')).digest('hex'))
            } catch (err) {
                reject(WXBizMsgCryptErrorCode.WXBizMsgCrypt_ComputeSignature_Error)
            }
        })

    }
}

module.exports = WXBizMsgCrypt