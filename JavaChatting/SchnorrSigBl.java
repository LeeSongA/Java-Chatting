import java.math.BigInteger;
import java.util.Scanner;
import java.security.*;

public class SchnorrSigBl {
   public static void main(String[] args) throws NoSuchAlgorithmException {
      Scanner s;
      s = new Scanner(System.in);
      
      // ------------------- Ű���� ----------------------
      System.out.println("1. Ű���� (Key Generation) "); 
      System.out.print("q�� ��Ʈ���� �Է��ϼ��� (160)>> ");
      int blq = s.nextInt();
      System.out.print("p�� ��Ʈ���� �Է��ϼ��� (1024)>> ");
      int blp = s.nextInt();
      
      BigInteger one = new BigInteger("1"); 
      BigInteger two = new BigInteger("2"); 
      BigInteger q, qp, p, a, g, xa, ya;
        int certainty = 10; // �Ҽ��� Ȯ���� ���Ѵ�.
        SecureRandom sr = new SecureRandom(); // ������ �����Ѵ�.        
       
        q = new BigInteger(blq, certainty, sr);   // blq ��Ʈ�� �Ҽ� 
        System.out.println("q = "+q); 
        
        // p = 2*q*qp+1 �� �Ҽ� p�� ���� 
      int i=0;
      qp = new BigInteger(blp-blq, certainty, sr);  // ��Ʈ���� blp-blq�� �Ҽ��� ������ ����  
      do {         
         p = q.multiply(qp).multiply(two).add(one); // p = 2*q*qp+1 �� ��� 
         if (p.isProbablePrime(certainty)) break;   // �̷��� ���� p�� �Ҽ��̸� ����  
         qp = qp.nextProbablePrime();               // �ƴϸ� �ٸ� �Ҽ��� �õ� 
         i++;
      } while (true);
      System.out.println("loop = "+i); 
      System.out.println("p = "+p); 
      System.out.println("p�� bit��  = "+p.bitLength()); 
      System.out.println();
      
      // g^q mod p = 1 �� �����ϴ� ������ g��  ���� 
      i=0;
      a = new BigInteger(blp-1, sr);  // blp ��Ʈ�� ���� ������ ����  
      do {         
         g = a.modPow((p.subtract(one)).divide(q),p); // g = a^((p-1)/q) mod p = a^(2*qp) mod p �� ��� 
         if(g.modPow(q, p).equals(one)) break;  // g^q mod p = 1 �̸� g�� �����ڷ� �����ϰ� break  
         a = a.add(one);  // �ƴϸ� �ٸ� ���� �õ� 
         i++;
      } while (true);
      System.out.println("loop = "+i);      
      System.out.println("g = "+g); 
      System.out.println("q|p-1 = "+(p.subtract(one)).mod(q)); // (p-1)�� q�� ������ �������� ������ Ȯ��   
      System.out.println("g^q mod p = "+g.modPow(q, p));  // �� ���� 1�� �Ǿ�� ��
      System.out.println();
      
      xa = new BigInteger(blq, sr);  // ����Ű�� ������ ���� 
      ya = g.modPow(xa, p);          // ����Ű ��� 
            
      System.out.println("A�� ����Ű: x = "+ xa);
      System.out.println("A�� ����Ű: y = "+ ya);
      System.out.println();
      
      // ------------------- ���� ���� ----------------------
      System.out.println("2. ���� ���� (Signing) ");
      String plaintext = "This is a simple message for Schnorr signature.";  // ������ �� 
      BigInteger k, U, W, V, H;  
      k = new BigInteger(blq, sr);  // k�� ������ ���� 
      U = g.modPow(k, p);           // U = g^k mod p 
         
      MessageDigest md = MessageDigest.getInstance("SHA1"); // SHA1 �ؽ��Լ��� �̿��Ͽ� 
      md.update(plaintext.getBytes());                  
      md.update(U.toString().getBytes());                
      byte[] digest = md.digest();                     // H(m,U)�� ���
      
      H = new BigInteger(1, digest);          // digest ���� BigInteger�� ��ȯ 
      V = (k.add(xa.multiply(H))).mod(q);      // V = (k + xa * H) mod q 
      System.out.println("m = "+plaintext);
      System.out.println("U = "+U);
      System.out.println("V = "+V);
      System.out.println("���� = (m,U,V)");
      System.out.println();
      
      // ------------------- ���� ���� ----------------------
      System.out.println("3. ���� ���� (Signature Verification) ");
      BigInteger left = g.modPow(V,p);         // ���ʰ� = g^V mod p ��� 
      
      MessageDigest md1 = MessageDigest.getInstance("SHA1");
      md1.update(plaintext.getBytes());
      md1.update(U.toString().getBytes());
      byte[] digest1 = md1.digest();               // H(m,U)�� ��� 
      
      BigInteger HH = new BigInteger(1, digest1); // digest ���� BigInteger�� ��ȯ 
      BigInteger right = (ya.modPow(HH,p).multiply(U)).mod(p);  // �����ʰ� = ya^HH * U mod p ���  

      System.out.println("Left  = "+left); 
      System.out.println("Right = "+right); 
      if(left.equals(right))                         // ����, ������ ���� ������ ������ ��ȿ 
         System.out.println("Schnorr signature is valid");
      else 
         System.out.println("Schnorr signature is not valid");
   }
}
