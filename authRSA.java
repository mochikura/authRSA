import java.security.*;
import java.util.*;

class authRSA{
    public static void main(String args[]){
        keyGen();
        signatureGen();
        signatureVeri();
    }
    public static void keyGen(){
        KeyPairGenerator KPGen=null;
        try{
            KPGen = KeyPairGenerator.getInstance("RSA");
        }catch(NoSuchAlgorithmException e){
            return;
        }
        SecureRandom rand=new SecureRandom();
        KPGen.initialize(2048,rand);
        KeyPair pairKey=KPGen.generateKeyPair();
        PublicKey PubKey=pairKey.getPublic();
        System.out.println("PublicKey:"+PubKey.getAlgorithm()+" "+PubKey.getFormat()+" "+PubKey.getEncoded());
        PrivateKey PriKey=pairKey.getPrivate();
        System.out.println("PrivateKey:"+PriKey.getAlgorithm()+" "+PriKey.getFormat()+" "+PriKey.getEncoded());
    }
    public static void signatureGen(){

    }
    public static void signatureVeri(){

    }
}