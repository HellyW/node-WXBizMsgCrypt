/*
 * @author: HellyW
 * @create_time: 2020-07-02
 * @update_time: 2020-07-03
 */


// WXBizMsgCrypt.js
// 内容加解密算法


const crypto = require('crypto')


const ALGORITHM = 'aes-256-cbc'
const MSG_LENGTH_SIZE = 4
const RANDOM_BYTES_SIZE = 16
const BLOCK_SIZE = 32

const PKCS7Decode = (buf) => {
    let pad = buf[buf.length - 1]
    if (pad < 1 || pad > 32) {
        pad = 0;
    }
    return buf.slice(0, buf.length - pad)
}

const PKCS7Encode = (buf) => {
    let padSize = BLOCK_SIZE - (buf.length % BLOCK_SIZE) // 计算填充的大小。
    let fillByte = padSize // 填充的字节数据为填充的大小
    let padBuf = Buffer.alloc(padSize, fillByte) // 分配指定大小的空间，并填充数据
    return Buffer.concat([buf, padBuf]) // 拼接原数据和填充的数据

}

class Cryptography {
    constructor(encodingAESKey) {
        this.key = Buffer.from(encodingAESKey + '=', 'base64')
        this.iv = this.key.slice(0, 16)
    }
    AES_decrypt(sEncryptMsg, EncodingAESKey) {
        return new Promise((resolve, reject) => {
            try {
                let encryptedMsgBuf = Buffer.from(sEncryptMsg, 'base64') // 将 base64 编码的数据转成 buffer
                let decipher = crypto.createDecipheriv(ALGORITHM, this.key, this.iv) // 创建解密器实例
                decipher.setAutoPadding(false) // 禁用默认的数据填充方式
                let decryptedBuf = Buffer.concat([decipher.update(encryptedMsgBuf), decipher.final()]) // 解密后的数据
                decryptedBuf = PKCS7Decode(decryptedBuf) // 去除填充的数据
                let msgSize = decryptedBuf.readUInt32BE(RANDOM_BYTES_SIZE) // 根据指定偏移值，从 buffer 中读取消息体的大小，单位：字节
                let msgBufStartPos = RANDOM_BYTES_SIZE + MSG_LENGTH_SIZE // 消息体的起始位置
                let msgBufEndPos = msgBufStartPos + msgSize // 消息体的结束位置
                let msgBuf = decryptedBuf.slice(msgBufStartPos, msgBufEndPos) // 从 buffer 中提取消息体
                resolve(msgBuf.toString())
            } catch (err) {
                reject(err)
            }
        })
    }
    AES_encrypt(sReplyMsg, m_sEncodingAESKey, m_sAppID) {
        return new Promise((resolve, reject) => {
            try {
                let randomBytes = crypto.randomBytes(RANDOM_BYTES_SIZE) // 生成指定大小的随机数据
                let msgLenBuf = Buffer.alloc(MSG_LENGTH_SIZE) // 申请指定大小的空间，存放消息体的大小
                let offset = 0 // 写入的偏移值
                msgLenBuf.writeUInt32BE(Buffer.byteLength(sReplyMsg), offset) // 按大端序（网络字节序）写入消息体的大小
                let msgBuf = Buffer.from(sReplyMsg) // 将消息体转成 buffer
                let appIdBuf = Buffer.from(m_sAppID) // 将 APPID 转成 buffer
                let totalBuf = Buffer.concat([randomBytes, msgLenBuf, msgBuf, appIdBuf]) // 将16字节的随机数据、4字节的消息体大小、若干字节的消息体、若干字节的APPID拼接起来
                let cipher = crypto.createCipheriv(ALGORITHM, this.key, this.iv) // 创建加密器实例
                cipher.setAutoPadding(false) // 禁用默认的数据填充方式
                totalBuf = PKCS7Encode(totalBuf) // 使用自定义的数据填充方式
                let encryptedBuf = Buffer.concat([cipher.update(totalBuf), cipher.final()]) // 加密后的数据
                resolve(encryptedBuf.toString('base64'))
            } catch (err) {
                reject(err)
            }
        })
    }
}

module.exports = Cryptography