import java.math.BigInteger;
import java.util.Scanner;
import java.security.*;

public class SchnorrSigBl {
   public static void main(String[] args) throws NoSuchAlgorithmException {
      Scanner s;
      s = new Scanner(System.in);
      
      // ------------------- 키생성 ----------------------
      System.out.println("1. 키생성 (Key Generation) "); 
      System.out.print("q의 비트수를 입력하세요 (160)>> ");
      int blq = s.nextInt();
      System.out.print("p의 비트수를 입력하세요 (1024)>> ");
      int blp = s.nextInt();
      
      BigInteger one = new BigInteger("1"); 
      BigInteger two = new BigInteger("2"); 
      BigInteger q, qp, p, a, g, xa, ya;
        int certainty = 10; // 소수일 확률을 정한다.
        SecureRandom sr = new SecureRandom(); // 난수를 생성한다.        
       
        q = new BigInteger(blq, certainty, sr);   // blq 비트의 소수 
        System.out.println("q = "+q); 
        
        // p = 2*q*qp+1 인 소수 p를 선택 
      int i=0;
      qp = new BigInteger(blp-blq, certainty, sr);  // 비트수가 blp-blq인 소수를 난수로 생성  
      do {         
         p = q.multiply(qp).multiply(two).add(one); // p = 2*q*qp+1 를 계산 
         if (p.isProbablePrime(certainty)) break;   // 이렇게 계산된 p가 소수이면 선택  
         qp = qp.nextProbablePrime();               // 아니면 다른 소수를 시도 
         i++;
      } while (true);
      System.out.println("loop = "+i); 
      System.out.println("p = "+p); 
      System.out.println("p의 bit수  = "+p.bitLength()); 
      System.out.println();
      
      // g^q mod p = 1 를 만족하는 생성자 g를  선택 
      i=0;
      a = new BigInteger(blp-1, sr);  // blp 비트의 수를 난수로 생성  
      do {         
         g = a.modPow((p.subtract(one)).divide(q),p); // g = a^((p-1)/q) mod p = a^(2*qp) mod p 를 계산 
         if(g.modPow(q, p).equals(one)) break;  // g^q mod p = 1 이면 g를 생성자로 선택하고 break  
         a = a.add(one);  // 아니면 다른 수를 시도 
         i++;
      } while (true);
      System.out.println("loop = "+i);      
      System.out.println("g = "+g); 
      System.out.println("q|p-1 = "+(p.subtract(one)).mod(q)); // (p-1)은 q로 나누어 떨어지는 수인지 확인   
      System.out.println("g^q mod p = "+g.modPow(q, p));  // 이 값은 1이 되어야 함
      System.out.println();
      
      xa = new BigInteger(blq, sr);  // 개인키를 난수로 선택 
      ya = g.modPow(xa, p);          // 공개키 계산 
            
      System.out.println("A의 개인키: x = "+ xa);
      System.out.println("A의 공개키: y = "+ ya);
      System.out.println();
      
      // ------------------- 서명 생성 ----------------------
      System.out.println("2. 서명 생성 (Signing) ");
      String plaintext = "This is a simple message for Schnorr signature.";  // 서명할 평문 
      BigInteger k, U, W, V, H;  
      k = new BigInteger(blq, sr);  // k를 난수로 선택 
      U = g.modPow(k, p);           // U = g^k mod p 
         
      MessageDigest md = MessageDigest.getInstance("SHA1"); // SHA1 해쉬함수를 이용하여 
      md.update(plaintext.getBytes());                  
      md.update(U.toString().getBytes());                
      byte[] digest = md.digest();                     // H(m,U)를 계산
      
      H = new BigInteger(1, digest);          // digest 값을 BigInteger로 변환 
      V = (k.add(xa.multiply(H))).mod(q);      // V = (k + xa * H) mod q 
      System.out.println("m = "+plaintext);
      System.out.println("U = "+U);
      System.out.println("V = "+V);
      System.out.println("서명 = (m,U,V)");
      System.out.println();
      
      // ------------------- 서명 검증 ----------------------
      System.out.println("3. 서명 검증 (Signature Verification) ");
      BigInteger left = g.modPow(V,p);         // 왼쪽값 = g^V mod p 계산 
      
      MessageDigest md1 = MessageDigest.getInstance("SHA1");
      md1.update(plaintext.getBytes());
      md1.update(U.toString().getBytes());
      byte[] digest1 = md1.digest();               // H(m,U)를 계산 
      
      BigInteger HH = new BigInteger(1, digest1); // digest 값을 BigInteger로 변환 
      BigInteger right = (ya.modPow(HH,p).multiply(U)).mod(p);  // 오른쪽값 = ya^HH * U mod p 계산  

      System.out.println("Left  = "+left); 
      System.out.println("Right = "+right); 
      if(left.equals(right))                         // 왼쪽, 오른쪽 값이 같으면 서명이 유효 
         System.out.println("Schnorr signature is valid");
      else 
         System.out.println("Schnorr signature is not valid");
   }
}
