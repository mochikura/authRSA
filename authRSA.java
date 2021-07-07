import java.security.*;
import java.util.*;

class authRSA{
    public static void main(String args[]){
        Scanner scan=new Scanner(System.in);
        SecureRandom rand=new SecureRandom();
        KeyPair pairKey=keyGen(rand);//キーペア生成
        PublicKey PubKey=pairKey.getPublic();//公開鍵
        PrivateKey PriKey=pairKey.getPrivate();//秘密鍵
        System.out.print("message:");
        String msg=scan.next();//署名元の文章入力
        byte[] sign=signatureGen(msg,PriKey,rand);//署名生成
        signatureVeri(msg, sign, PubKey);//署名検証
    }
    public static KeyPair keyGen(SecureRandom rand){
        KeyPairGenerator KPGen=null;
        try{
            KPGen = KeyPairGenerator.getInstance("RSA");//鍵方式決定
        }catch(NoSuchAlgorithmException e){
            return null;
        }
        KPGen.initialize(2048,rand);//鍵生成の初期化
        KeyPair pairKey=KPGen.generateKeyPair();//キーペアの生成
        PublicKey PubKey=pairKey.getPublic();//公開鍵の取得
        System.out.println("PublicKey:"+PubKey.getAlgorithm()+" "+PubKey.getFormat()+" "+PubKey.getEncoded());
        PrivateKey PriKey=pairKey.getPrivate();//秘密鍵の取得
        System.out.println("PrivateKey:"+PriKey.getAlgorithm()+" "+PriKey.getFormat()+" "+PriKey.getEncoded());
        return pairKey;
    }
    public static byte[] signatureGen(String msg, PrivateKey PriKey,SecureRandom rand){
        Signature sign=null;
        byte[] RTSign=null;
        try{
            sign =Signature.getInstance("SHA256withRSA");//署名方式決定
            sign.initSign(PriKey,rand);//署名の初期化
            sign.update(msg.getBytes());//署名をメッセージを元に生成
            RTSign=sign.sign();//署名をbyteとして格納
            System.out.println("Sign:"+sign);
        }catch(Exception e){
            e.printStackTrace();
        }
        return RTSign;
    }
    public static void signatureVeri(String msg, byte[] RTSign, PublicKey PubKey){
        Signature signVery=null;
        try{
            signVery=Signature.getInstance("SHA256withRSA");//署名検証方式決定
            signVery.initVerify(PubKey);//署名検証の初期化
            signVery.update(msg.getBytes());//署名検証するためのメッセージを検証する形にする
            System.out.println(signVery.verify(RTSign));//検証
        }catch(Exception e){
            e.printStackTrace();
        }
    }
}