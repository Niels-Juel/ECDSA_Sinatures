package common;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import javax.annotation.PostConstruct;
import javax.ejb.Stateless;
import javax.ejb.LocalBean;

/**
 *
 * @author a.shalin
 */
@Stateless
@LocalBean
public class Enforce {
    private KeyPair pair;
    
    /*
    * Генерирует сигнатуру ECDSA для строки
    */
    public String getEcdsaSign(String value, PrivateKey privatekey) throws NoSuchAlgorithmException, 
            InvalidAlgorithmParameterException, InvalidKeyException, 
            UnsupportedEncodingException, SignatureException {
        /*
        * Создание пары ключей
        */
//        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
//        keyGen.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
//        KeyPair pair = keyGen.generateKeyPair();
//        PrivateKey priv = pair.getPrivate();
//        PublicKey pub = pair.getPublic();

        /*
         * Create a Signature object and initialize it with the private key
         */
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(privatekey);
        byte[] strByte = value.getBytes("UTF-8");
        ecdsa.update(strByte);
        byte[] realSig = ecdsa.sign();
        return new BigInteger(1, realSig).toString(16);
    }
    
    @PostConstruct
    private void generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
            this.pair = keyGen.generateKeyPair();
        } 
        catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException ex) {
            System.out.println(ex.getCause());
        }
    }
    
    public KeyPair getKeyPair() {
        return this.pair;
    }
    
    public PrivateKey getPrivateKey() {
        return this.pair.getPrivate();
    }
    
    public PublicKey getPublicKey() {
        return this.pair.getPublic();
    }
}
