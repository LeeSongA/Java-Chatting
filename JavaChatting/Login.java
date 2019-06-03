import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

import org.spongycastle.openssl.PEMWriter;
import org.spongycastle.util.io.pem.PemObjectGenerator;
import org.spongycastle.util.io.pem.PemWriter;

@SuppressWarnings("serial")
public class Login extends JFrame {

   private int type;                        // ���� ����
   
   private Login login;
   private JLabel label;
   private JPanel loginPanel, inputPanel;
   private JTextField idField;
   private JPasswordField pwdField;
   private JButton loginButton;

   private final int SIZE_SCREEN_WIDTH = 400;      // ������ ����
   private final int SIZE_SCREEN_HEIGHT = 200;
   private final int SIZE_LABEL_HEIGHT = 100;
   private final int SIZE_LOGIN_PANEL_WIDTH = 380;
   private final int SIZE_LOGIN_PANEL_HEIGHT = 200;
   private final int SIZE_FIELD_HEIGHT = 30;
   private final int SIZE_FIELD_MARGIN_X = 0;
   private final int SIZE_BUTTON_WIDTH = 100;
   private final int SIZE_BUTTON_HEIGHT = 70;
   private final int SIZE_FIELD_MARGIN_Y = 10;
   
   private PublicKey publicKey_s = null;
   private PrivateKey privateKey_c = null;
   
   public Login(int type) {
      super("Login");
      
      checkServer();

      login = this;
      this.type = type;

      setLayout(new BoxLayout(this.getContentPane(), BoxLayout.Y_AXIS));

      label = new JLabel("ä�� ���α׷�");
      label.setPreferredSize(new Dimension(SIZE_SCREEN_WIDTH, SIZE_LABEL_HEIGHT));
      label.setHorizontalAlignment(SwingConstants.CENTER);

      loginPanel = new JPanel();
      loginPanel.setPreferredSize(new Dimension(SIZE_LOGIN_PANEL_WIDTH,SIZE_LOGIN_PANEL_HEIGHT));
      
      inputPanel = new JPanel();
      inputPanel.setLayout(new GridLayout(2,1,SIZE_FIELD_MARGIN_X,SIZE_FIELD_MARGIN_Y));
      idField = new JTextField(" ���̵� �Է��ϼ���");
      idField.setPreferredSize(new Dimension(SIZE_LOGIN_PANEL_WIDTH - SIZE_BUTTON_WIDTH - 10, SIZE_FIELD_HEIGHT));
      
      pwdField = new JPasswordField("��й�ȣ�� �Է��ϼ���");
      pwdField.setPreferredSize(new Dimension(SIZE_LOGIN_PANEL_WIDTH - SIZE_BUTTON_WIDTH - 10, SIZE_FIELD_HEIGHT));
      
      loginButton = new JButton("�α���");
      loginButton.setPreferredSize(new Dimension(SIZE_BUTTON_WIDTH, SIZE_BUTTON_HEIGHT));
      
      inputPanel.add(idField,0);
      inputPanel.add(pwdField,1);
      
      loginPanel.add(inputPanel);
      loginPanel.add(loginButton);

      clickEvent(idField, pwdField, loginButton);
      
      add(label);
      add(loginPanel);

      setSize(SIZE_SCREEN_WIDTH,SIZE_SCREEN_HEIGHT);
      setResizable(false);
      setVisible(true);
      setLocationRelativeTo(null);
      
      loginButton.requestFocus();
   }
   
   void checkServer() {
      URL url = null;
      URLConnection connection = null;
      String data = "";
         
      try {
          url = new URL("http://localhost:8000/pub");
          connection = url.openConnection();
          BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
          String str;
          while((str = in.readLine())!=null) { data+=str; }
      } catch(Exception e){
         JOptionPane.showMessageDialog(null, "ä�� ������ ���� ������ �ʽ��ϴ�");
         System.exit(1);
      }
      data = data.replace("-----BEGIN PUBLIC KEY-----", "");
        data = data.replace("-----END PUBLIC KEY-----", "");
      
        try {
         publicKey_s = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec (Base64.getDecoder().decode(data)));
      } catch (Exception e) {
         e.printStackTrace();
         JOptionPane.showMessageDialog(null, "���α׷� ������ �߻��߽��ϴ�");
         System.exit(1);
      }
   }
   
   void clickEvent(JTextField idField, JPasswordField pwdField, JButton loginButton) {
      // idField Ŭ���ϸ� "���̵� �Է��ϼ���" ���� ������
      idField.addMouseListener(new MouseListener() {

         @Override
         public void mouseClicked(MouseEvent arg0) {}

         @Override
         public void mouseEntered(MouseEvent arg0) {}

         @Override
         public void mouseExited(MouseEvent arg0) {}

         @Override
         public void mousePressed(MouseEvent arg0) {
            // TODO Auto-generated method stub
            if(idField.getText().equals(" ���̵� �Է��ϼ���"))
               idField.setText("");
         }

         @Override
         public void mouseReleased(MouseEvent arg0) {}
      });
      
      // pwdField Ŭ���ϸ� pwdField �ʱ�ȭ
      pwdField.addFocusListener(new FocusListener() {

         @SuppressWarnings("deprecation")
         @Override
         public void focusGained(FocusEvent arg0) {
            // TODO Auto-generated method stub
            if(pwdField.getText().equals("��й�ȣ�� �Է��ϼ���"))
               pwdField.setText("");
         }

         @Override
         public void focusLost(FocusEvent arg0) {
            // TODO Auto-generated method stub
            
         }
         
      });
      
      // loginButton Ŭ���ϸ�
      loginButton.addMouseListener(new MouseListener() {

         @Override
         public void mouseClicked(MouseEvent arg0) {}

         @Override
         public void mouseEntered(MouseEvent arg0) {}

         @Override
         public void mouseExited(MouseEvent arg0) {}

         @Override
         public void mousePressed(MouseEvent arg0) {
            // TODO Auto-generated method stub
            String id = idField.getText();
            @SuppressWarnings("deprecation")
            String pwd = pwdField.getText();
            String result = "";
            
            if(id.equals("") || id.equals(" ���̵� �Է��ϼ���"))
               JOptionPane.showMessageDialog(null, "���̵� �Է��ϼ���");
            else if(pwd.equals("") || pwd.equals("��й�ȣ�� �Է��ϼ���"))
               JOptionPane.showMessageDialog(null, "��й�ȣ�� �Է��ϼ���");
            else {
               URL url = null;
               URLConnection connection = null;
               String cipherText = "";
               
               try {
                  Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
                  cipher.init(Cipher.ENCRYPT_MODE, publicKey_s);
                  cipherText = new String(Base64.getEncoder().encode(cipher.doFinal(getMD5(pwd.getBytes()))));
               } catch (Exception e) {
                  e.printStackTrace();
                  JOptionPane.showMessageDialog(null, "���α׷� ������ �߻��߽��ϴ�");
                  System.exit(1);
               }
               
               try {
                  cipherText = cipherText.replace('+','!');         // +���ڰ� ������ �ȵǼ� !���ڷ� ġȯ�ؼ� ����
                  
                  String query = "?id="+id+"&pwd="+cipherText;
                   url = new URL("http://localhost:8000"+query);
                   connection = url.openConnection();
                   BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                   result = in.readLine();
               } catch(Exception e){
                  JOptionPane.showMessageDialog(null, "ä�� ������ ������ ������ϴ�");
                  System.exit(1);
               }
               
               if(result.equals("OK")) {
                  if(type == 0) {
                     Server app = netw Server(id); 
                     app.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                  } else {
                     String desthost = "localhost";
                     
                     Client app = new Client(id, desthost);
                     
                     app.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                  }
                  login.dispose();
               }
               else {
                  JOptionPane.showMessageDialog(null, "�α��ο� �����߽��ϴ�.");
               }
            }
         }

         @Override
         public void mouseReleased(MouseEvent arg0) {}
      });
   }
   
   public byte[] getMD5(byte[] pwd) {
      StringBuffer buffer = null;
      try{

         MessageDigest md = MessageDigest.getInstance("MD5"); 
         md.update(pwd); 
         byte temp[] = md.digest();
         buffer = new StringBuffer(); 
         for(int i = 0 ; i < temp.length ; i++)
            buffer.append(Integer.toString((temp[i]&0xff) + 0x100, 16).substring(1));
      }catch(Exception e){
         JOptionPane.showMessageDialog(null, "���α׷� ������ �߻��߽��ϴ�");
         System.exit(1);
      }
      return buffer.toString().getBytes();
   }
}