package com.eHanlin.api.invoice.pay2go.crypto

import spock.lang.*

import javax.crypto.Cipher
import java.security.Security


/**
 * 執行這個測試時需要啟用無限制加密
 *
 * java 版本 8u151 開始可以透過設定安全特性，啟用無限制加密，否則測試前必須手動加裝 JCE 套件到 JRE 中
 */
@Requires({
    Security.setProperty("crypto.policy", "unlimited")
    Cipher.getMaxAllowedKeyLength("AES") >= 256
})
class Pay2GoCryptoSpec extends Specification {

    @Shared hashKey = "12345678901234567890123456789012"

    @Shared hashIV = "1234567890123456"

    @Shared pay2GoCrypto = new Pay2GoCrypto(hashKey, hashIV)

    @Shared examplePlainText = [
                MerchantID: "3430112",
                RespondType: "JSON",
                TimeStamp: "1485232229",
                Version: "1.4",
                MerchantOrderNo: "S_1485232229",
                Amt: "40",
                ItemDesc: "UnitTest"
            ].collect().join("&")

    @Shared exampleAesEncryptedText =
                "ff91c8aa01379e4de621a44e5f11f72e4d25bdb1a18242db6cef9ef07d80b0165" +
                "e476fd1d9acaa53170272c82d122961e1a0700a7427cfa1cf90db7f6d6593bbc9" +
                "3102a4d4b9b66d9974c13c31a7ab4bba1d4e0790f0cbbbd7ad64c6d3c8012a601" +
                "ceaa808bff70f94a8efa5a4f984b9d41304ffd879612177c622f75f4214fa"

    def "智付系列 AES 加密"() {
        expect:
        pay2GoCrypto.encrypt(examplePlainText) == exampleAesEncryptedText
    }

    def "智付系列 AES 解密"() {
        expect:
        pay2GoCrypto.decrypt(exampleAesEncryptedText) == examplePlainText
    }

    def "智付系列 SHA-256 訊息摘要"() {
        given:
        def plainDigestText = "HashKey=${hashKey}&${exampleAesEncryptedText}&HashIV=${hashIV}"
        def exampleSha256Digest = "EA0A6CC37F40C1EA5692E7CBB8AE097653DF3E91365E6A9CD7E91312413C7BB8"

        expect:
        pay2GoCrypto.sha256(plainDigestText).toUpperCase() == exampleSha256Digest
    }

    def "加解密過程是執行緒安全的"() {
        when:
        def results = [:]

        (1..500).collect { n ->
            Thread.start {
                try {
                    def plainText = "thread=$n&" + examplePlainText
                    def encryptedText = pay2GoCrypto.encrypt(plainText)
                    results[n] = (pay2GoCrypto.decrypt(encryptedText) == plainText)
                } catch (Exception e) {
                    results[n] = false
                }
            }
        }*.join()

        then:
        results.every { it.value == true }
    }

}

