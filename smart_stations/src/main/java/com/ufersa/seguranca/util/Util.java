package com.ufersa.seguranca.util;

import java.util.zip.CRC32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/*
 * Métodos utilitários para cálculos de integridade e autenticação.
*/

public class Util {

    public static long calcularCRC32(byte[] bytesMensagem) {
        CRC32 crc = new CRC32();
        crc.update(bytesMensagem);
        return crc.getValue();
    }

    public static byte[] calcularHmacSha256(byte[] chave, byte[] bytesMensagem) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(chave, "HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(bytesMensagem);
    }
}
