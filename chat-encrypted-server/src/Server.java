/* 
 * 
 * 201720857 사이버보안학과 김영표 
 * 네트워크 보안 및 실습 프로젝트 Server
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

import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.ServerSocket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Server {
    /**
     * RSA 복호화
     * 
     * @param String     encrypted base64 encode된 암호문
     * @param PrivateKey privateKey 복호화에 사용되는 개인키
     * @return byte[] 형태의 평문
     * @exception
     * 
     */
    public static byte[] decryptRSA(String encrypted, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        byte[] byteEncrypted = Base64.getDecoder().decode(encrypted);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] bytePlain = cipher.doFinal(byteEncrypted);
        // String decrypted = new String(bytePlain, "utf-8");
        return bytePlain;
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

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        int port = 7777;
        System.out.print("Port: ");
        port = sc.nextInt();
        // 버퍼 비워주기
        sc.nextLine();
        // 예외 처리하기 편하게 그냥 try로 싹 묶음
        try {
            // 서버 Socket 생성
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("> ServerSocket awaiting connections...");

            // 누군가 연결할때까지 대기
            Socket socket = serverSocket.accept();

            // 클라이언트로 데이터를 보낼 Output Stream
            OutputStream outputStream = socket.getOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);

            // 클라이언트로부터 데이터를 받을 Input Stream
            InputStream inputStream = socket.getInputStream();
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);

            // Generate RSA-2048 Public Key
            System.out.println("> Creating RSA Key Pair...");
            SecureRandom secureRandom = new SecureRandom();
            KeyPairGenerator gen;
            gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048, secureRandom);
            KeyPair rsaKeyPair = gen.genKeyPair();
            System.out.println("Private Key: " + new String(byteArrayToHex(rsaKeyPair.getPrivate().getEncoded())));
            System.out.println("Public Key: " + new String(byteArrayToHex(rsaKeyPair.getPublic().getEncoded())));
            System.out.println("");

            // Sending RSA Public Key
            objectOutputStream.writeObject(rsaKeyPair.getPublic());

            // Receive RSA Encrypted AES Secret key
            String encryptedAesKey = (String) objectInputStream.readObject();

            // RSA Decrypt AES Secret Key
            byte[] decryptedAesKey = decryptRSA(encryptedAesKey, rsaKeyPair.getPrivate());
            SecretKey aesKey = new SecretKeySpec(decryptedAesKey, 0,
                    decryptedAesKey.length, "AES");
            System.out.println("> Received AES Key: " + encryptedAesKey);
            System.out.println("Decrypted AES Key: " + new String(byteArrayToHex(decryptedAesKey)));
            System.out.println("");

            // Receive RSA Encrypted IV
            String encryptedIv = (String) objectInputStream.readObject();

            // RSA Decrypt CBC IV
            byte[] iv = decryptRSA(encryptedIv, rsaKeyPair.getPrivate());
            System.out.println("> Received CBC IV: " + encryptedIv);
            System.out.println("Decrypted CBC IV: " + new String(byteArrayToHex(iv)));
            System.out.println("");

            // 송신할 메시지 (암호화 및 base64 encode)
            String sendEncryptedMessage;
            // 수신한 메시지 (암호화 및 base64 encode)
            String receivedEncryptedMessage;
            // 송신할 메시지 (평문)
            String sendMessage;
            // 수신한 메시지 (평문)
            byte[] receivedMessage;
            while (true) {
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
            }
            System.out.println("Connection closed.");
            // Socket 종료
            socket.close();
            serverSocket.close();
        } catch (Exception e) {
            System.out.println(e);
        }
        sc.close();
        return;
    }

}
