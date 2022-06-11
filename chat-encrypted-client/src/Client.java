/* 
 * 
 * 201720857 사이버보안학과 김영표 
 * 네트워크 보안 및 실습 프로젝트 Client
 * 아래 Reference 문서들을 참고하여 작성함
 * 
 */
/* Reference */
//http://stackoverflow.com/questions/9655181/convert-from-byte-array-to-hex-string-in-java
//https://offbyone.tistory.com/346
//https://jgrammer.tistory.com/entry/Java-%EC%86%8C%EC%BC%93-%ED%86%B5%EC%8B%A0-%EA%B0%84%EB%8B%A8%ED%95%9C-%EC%B1%84%ED%8C%85-%ED%94%84%EB%A1%9C%EA%B7%B8%EB%9E%A8-%EA%B5%AC%ED%98%84
//https://gist.github.com/chatton/14110d2550126b12c0254501dde73616
//https://m.blog.naver.com/PostView.naver?isHttpsRedirect=true&blogId=loverman85&logNo=221090063698
//https://stackoverflow.com/questions/18228579/how-to-create-a-secure-random-aes-key-in-java
//http://www.fun25.co.kr/blog/java-aes128-cbc-encrypt-decrypt-example
//https://dev-coco.tistory.com/31
//https://devbible.tistory.com/451

/* Test */
//https://the-x.cn/en-US/cryptography/Aes.aspx

import java.util.Scanner;
import java.net.Socket;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Client {
    /**
     * byte[]를 Hex String으로 변환
     * Ke 또는 IV 출력시 사용
     * 
     * @param byte a String으로 변경할 byte Array
     * @return String에 a의 Hex값이 담김
     * @exception
     * 
     */
    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /**
     * RSA 암호화
     * 
     * @param byte[]    plainText 암호화 할 평문
     * @param PublicKey publicKey 암호화에 사용되는 공개키
     * @return base64로 encode된 암호문
     * @exception
     * 
     */
    public static String encryptRSA(byte[] plainText, PublicKey publicKey)
            throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytePlain = cipher.doFinal(plainText);
        String encrypted = Base64.getEncoder().encodeToString(bytePlain);
        return encrypted;
    }

    /**
     * AES 암호화
     * 
     * @param byte[]    plainText 암호화 할 평문
     * @param SecretKey key 암호화에 사용되는 비밀키
     * @return base64로 encode된 암호문
     * @exception
     * 
     */
    public static String encryptAES(byte[] plainText, SecretKey key, byte[] iv) throws Exception {
        // PKCS5와 PKCS7은 같음
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] bytePlain = cipher.doFinal(plainText);
        String encrypted = Base64.getEncoder().encodeToString(bytePlain);
        return encrypted;
    }

    /**
     * AES 복호화
     * 
     * @param String    encrypted 복호화할 base64 String
     * @param SecretKey key 복호화에 사용되는 비밀키
     * @param byte[]    iv CBC 모드 Initial Vector
     * @return base64로 encode된 암호문
     * @exception
     * 
     */
    public static byte[] decryptAES(String encrypted, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] byteEncrypted = Base64.getDecoder().decode(encrypted);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] bytePlain = cipher.doFinal(byteEncrypted);
        // String decrypted = new String(bytePlain, "utf-8");
        return bytePlain;
    }

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        int port = 65535;
        String host = "localhost";

        System.out.print("Host: ");
        host = sc.next();
        // 버퍼 비워줌(Enter)
        sc.nextLine();
        System.out.print("Port: ");
        port = sc.nextInt();

        // 예외 처리하기 편하게 그냥 try로 싹 묶음
        try {
            // Socket 연결
            Socket socket = new Socket(host, port);
            System.out.println("> Server Connected!");

            // 서버로부터 데이터를 받을 Input Stream
            InputStream inputStream = socket.getInputStream();
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);

            // 서버로 데이터를 보낼 Output Stream
            OutputStream outputStream = socket.getOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);

            // Get RSA-2048 Public Key from Server
            PublicKey rsaPubKey = (PublicKey) objectInputStream.readObject();
            System.out.println("Received Public Key: " + new String(byteArrayToHex(rsaPubKey.getEncoded())));

            // Generate AES-256 Key
            System.out.println("> Creating AES Key...");
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // for example
            SecretKey aesKey = keyGen.generateKey();

            // Encrypt AES Secret Key with RSA
            System.out.println("AES 256 Key: " + new String(byteArrayToHex(aesKey.getEncoded())));
            String encryptedAESKey = encryptRSA(aesKey.getEncoded(), rsaPubKey);
            System.out.println("Encrypted AES 256 Key: " + encryptedAESKey);
            System.out.println("");

            // Sending AES Secret Key
            objectOutputStream.writeObject(encryptedAESKey);

            // Generate IV for CBC
            System.out.println("> Generate IV...");
            SecureRandom randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");
            byte[] iv = new byte[16];
            randomSecureRandom.nextBytes(iv);

            // Encrypt CBC IV Using RSA
            System.out.println("CBC IV: " + new String(byteArrayToHex(iv)));
            String encryptedIV = encryptRSA(iv, rsaPubKey);

            // Sending Encrypted IV
            System.out.println("Encrypted CBC IV: " + encryptedIV);
            System.out.println("");
            objectOutputStream.writeObject(encryptedIV);

            // 송신할 메시지 (암호화 및 base64 encode)
            String sendEncryptedMessage;
            // 수신한 메시지 (암호화 및 base64 encode)
            String receivedEncryptedMessage;
            // 송신할 메시지 (평문)
            String sendMessage;
            // 수신한 메시지 (평문)
            byte[] receivedMessage;
            while (true) {
                // String 형태로 Input Stream으로부터 메시지를 읽음
                receivedEncryptedMessage = (String) objectInputStream.readObject();

                // 수신 시간 확인
                LocalDateTime now = LocalDateTime.now();
                String formatedNow = now.format(DateTimeFormatter.ofPattern("[yyyy/MM/dd HH:mm:ss]"));

                // 받은 메시지 복호화
                receivedMessage = decryptAES(receivedEncryptedMessage, aesKey, iv);

                // 수신한 메시지 출력
                System.out.println("> Received: \"" + new String(receivedMessage) + "\" " + formatedNow);
                System.out.println("Encrypted Message: \"" + receivedEncryptedMessage + "\"");

                // 수신한 메시지가 종료 사인인지 확인
                if (new String(receivedMessage).equals("exit")) {
                    break;
                }
                System.out.println("");

                // 송신할 메시지 입력 대기
                System.out.print("> ");
                sendMessage = sc.nextLine();

                // 송신할 메시지 암호화
                sendEncryptedMessage = encryptAES(sendMessage.getBytes(), aesKey, iv);

                // Output Stream에 암호문 write
                objectOutputStream.writeObject(sendEncryptedMessage);

                // 송신 메시지가 종료 사인이면 while 탈출
                if (sendMessage.equals("exit")) {
                    break;
                }
            }
            System.out.println("Connection closed.");
            // Socket 닫음
            socket.close();
        } catch (Exception e) {
            System.out.println(e);
        }

        sc.close();
        return;
    }

}