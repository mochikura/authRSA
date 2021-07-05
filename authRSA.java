import java.security.*;
import java.util.*;

class authRSA{
    public static void main(String args[]){
        Scanner scan=new Scanner(System.in);
        SecureRandom rand=new SecureRandom();
        KeyPair pairKey=keyGen(rand);
        PublicKey PubKey=pairKey.getPublic();
        PrivateKey PriKey=pairKey.getPrivate();
        System.out.print("message:");
        String msg=scan.next();
        byte[] sign=signatureGen(msg,PriKey,rand);
        signatureVeri(msg, sign, PubKey);
    }
    public static KeyPair keyGen(SecureRandom rand){
        KeyPairGenerator KPGen=null;
        try{
            KPGen = KeyPairGenerator.getInstance("RSA");
        }catch(NoSuchAlgorithmException e){
            return null;
        }
        KPGen.initialize(2048,rand);
        KeyPair pairKey=KPGen.generateKeyPair();
        PublicKey PubKey=pairKey.getPublic();
        System.out.println("PublicKey:"+PubKey.getAlgorithm()+" "+PubKey.getFormat()+" "+PubKey.getEncoded());
        PrivateKey PriKey=pairKey.getPrivate();
        System.out.println("PrivateKey:"+PriKey.getAlgorithm()+" "+PriKey.getFormat()+" "+PriKey.getEncoded());
        return pairKey;
    }
    public static byte[] signatureGen(String msg, PrivateKey PriKey,SecureRandom rand){
        Signature sign=null;
        byte[] RTSign=null;
        try{
            sign =Signature.getInstance("SHA256withRSA");
            sign.initSign(PriKey,rand);
            sign.update(msg.getBytes());
            RTSign=sign.sign();
            System.out.println("Sign:"+sign);
        }catch(Exception e){
            e.printStackTrace();
        }
        return RTSign;
    }
    public static void signatureVeri(String msg, byte[] RTSign, PublicKey PubKey){
        Signature signVery=null;
        try{
            signVery=Signature.getInstance("SHA256withRSA");
            signVery.initVerify(PubKey);
            signVery.update(msg.getBytes());
            System.out.println(signVery.verify(RTSign));
        }catch(Exception e){
            e.printStackTrace();
        }
    }
}