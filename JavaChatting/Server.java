import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.crypto.*;
import javax.crypto.spec.*;
import sun.misc.*;

@SuppressWarnings("serial")
public class Server extends JFrame implements ActionListener {
   private String id;

   private JPanel panel;
   private JTextField textfield; 					// JTextField ����
   private JTextArea textarea; 						// JTextArea ����
   private JRadioButton normaltext; 				// Plain Text ��ư ����
   private JRadioButton ciphertext; 				// Cipher Text ��ư ����
   private ButtonGroup radioGroup;
   private JButton buttonFile; 						// File Button �����߰��ϱ� ��ư
   private JFileChooser jfc;
   private Cipher c;
   private ObjectOutputStream output;
   private ObjectInputStream input;
   private ServerSocket ss, ss2;
   private Socket s, s2;
   private DataOutputStream dout;
   private DataInputStream din;
   private Boolean keyset = true; 					// Ű�� �ѹ��� �Է¹ް� �ϱ� ���� ����
   private int inctrl; 								// ���� �޽����� ��ȣ������ �ƴ����� ��Ÿ���� ��Ʈ��, 0:���빮, 1:��ȣ��, 2:key
   private int outctrl = 0; 						// ���� �޽����� ��ȣ������ �ƴ����� ��Ÿ���� ��Ʈ��, 0:���빮, 1:��ȣ��
   static public int destport = 5432;

   private SecretKeySpec deskey;
   private PrivateKey key_me;
   private PublicKey key_other, publicKey;
   private Signature signature_me, signature_other;

   public Server(String id) {
      super("TCPstalkServer"); 						// Serverȭ�� Ÿ��Ʋ TCPstalkSever

      this.id = id;
      initGUI();
      createDSAKey();

      new Thread() {
         public void run() {
            runServer();
         }
      }.start();
      
      new Thread() {
         public void run() {
            try {
               ss2 = new ServerSocket(destport + 1);
               s2 = ss2.accept();

               dout = new DataOutputStream(s2.getOutputStream());
               din = new DataInputStream(s2.getInputStream());

               while (true) {
                  int data = din.readInt();
                  String filename = din.readUTF();
                  File file = new File(filename);
                  FileOutputStream out = new FileOutputStream(file);

                  byte[] buffer = new byte[1024];
                  for (int len; data > 0; data--) {
                     len = s2.getInputStream().read(buffer);
                     out.write(buffer, 0, len);
                  }
                  out.flush();
                  
                  buffer = new byte[46];
                  s2.getInputStream().read(buffer);
                  signature_other = Signature.getInstance("SHA1withDSA", "SUN");
                  signature_other.initVerify(key_other);
                  signature_other.update(Files.readAllBytes(Paths.get(filename)));
                  if(signature_other.verify(buffer)) {
                     sendData(id + "&nbsp;������ �Ϸ�Ǿ����ϴ�");
                     textfield.setText("");
                  }else {
                     sendData(id + "&nbsp;������ ����! ������ �����Ǿ����ϴ�.");
                     textfield.setText("");
                     new File(filename).delete();
                  }
               }
            } catch (Exception e) {
               e.printStackTrace();
            }
         }
      }.start();
   }

   public void initGUI() {
      panel = new JPanel(); 									// ������ư�� Ű �Է��� �� �г�
      panel.setLayout(new FlowLayout());

      textfield = new JTextField(); 							// Ű �Է��� �ʵ�
      textfield.setEditable(false); 							// ������ �Ұ����ϰ� ��. ����Ǹ� ���� ����
      textfield.addActionListener(new ActionListener() {
         public void actionPerformed(ActionEvent event) {
            sendData(id + "&nbsp;" + event.getActionCommand()); // �Է��ϸ� �޽����� sendData�޼ҵ��� ���ڷ� �ѱ�
            textfield.setText(""); 								// textfield �ʱ�ȭ
         }
      });
      add(textfield, BorderLayout.NORTH); 						// textfield ��ġ ����, ������ ���ʿ� �߰�

      textarea = new JTextArea();
      textarea.setEditable(false); 								// ��µǴ� �κ��̱� ������ ������ �Ұ����ϰ� ��
      add(new JScrollPane(textarea), BorderLayout.CENTER); 		// textarea ��ġ ����, ������ �߾ӿ� ��ũ�� �ٿ��� �߰�

      normaltext = new JRadioButton("Plain Text", true); 		// ���빮���� �����ϴ� ��ư
      normaltext.addActionListener(new ActionListener() {
         public void actionPerformed(ActionEvent event) {
            String sendctrl = "ctrl>>0";
            try {
               output.writeObject(sendctrl);
            } catch (IOException e) {
            }
            outctrl = 0;
         }
      });

      panel.add(normaltext);

      ciphertext = new JRadioButton("Cipher Text", false);
      ciphertext.addActionListener(new ActionListener() {
         public void actionPerformed(ActionEvent event) {
            if (keyset)
               InputKey();

            try {
               String sendctrl = "ctrl>>1";
               output.writeObject(sendctrl);
               outctrl = 1;
            } catch (IOException e) {
            }
         }
      });

      panel.add(ciphertext);

      radioGroup = new ButtonGroup();
      radioGroup.add(normaltext);
      radioGroup.add(ciphertext);

      buttonFile = new JButton("File");
      buttonFile.addActionListener(this);
      panel.add(buttonFile);

      jfc = new JFileChooser();
      jfc.setFileFilter(new FileNameExtensionFilter("txt", "txt"));
      jfc.setMultiSelectionEnabled(false); 					// ���� ���� �Ұ�

      add(panel, BorderLayout.SOUTH);

      setSize(400, 500); 									// ������ ũ��
      setVisible(true); 									// ȭ�鿡 ���̰� ��.
   }

   public void createDSAKey() {
      try {
         KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA", "SUN");
         generator.initialize(1024, new SecureRandom());

         KeyPair keyPair = generator.generateKeyPair();
         key_me = keyPair.getPrivate();

         signature_me = Signature.getInstance("SHA1withDSA", "SUN");
         signature_me.initSign(key_me);

         publicKey = keyPair.getPublic();
      } catch (Exception e) {
         e.printStackTrace();
      }
   }

   public void runServer() { 								// ��� ����Ǵ� ��ƾ�� �ִ� �޼ҵ�
      try {
         ss = new ServerSocket(destport);

         while (true) {
            try {
               s = ss.accept(); 							// Ŭ���̾�Ʈ�� ������ ���⸦ ��ٸ�.
               exchangeKey();
               getStream(); 								// ����� Stream�� ��� �޼ҵ�
               process(); 									// ���� ����� Stream���� �޼����� ������ ����.
            } catch (Exception e) {
               textarea.append("\nTerminated");
            } finally { 									// ����������(������) closeConnection() ����
               closeConnection();
            }
         }
      } catch (IOException ioe) {
         textarea.append("no socket available");
      }
   }

   private void InputKey() {
      String Ikey = JOptionPane.showInputDialog("8����  Key�� �Է��ϼ���");
      if (Ikey.length() == 8) {
         deskey = new SecretKeySpec(Ikey.getBytes(), "DES");
         keyset = false;
      } else {
         JOptionPane.showMessageDialog(null, "8���ڸ� �Է��� �ּ���.");
         InputKey();
      }
   }

   public void exchangeKey() {
      try {
         output = new ObjectOutputStream(s.getOutputStream());
         output.writeObject(publicKey.getEncoded());

         input = new ObjectInputStream(s.getInputStream());
         byte[] data = (byte[]) input.readObject();
         key_other = KeyFactory.getInstance("DSA", "SUN").generatePublic(new X509EncodedKeySpec(data));
      } catch (Exception e) {
         e.printStackTrace();
      }
   }

   // ����� ��Ʈ���� ����
   private void getStream() throws IOException {
      output.writeObject("DSA ����Ű�� �����߽��ϴ�:" + publicKey.getEncoded());
      output.flush();
   }

   // Ŭ���̾�Ʈ�� ����� �� ó��(Ŭ���̾�Ʈ�� ������ ���� �޼��� ó��)
   private void process() throws IOException, ClassNotFoundException {
      /*
       * String message = "Connection successful"; sendData(message); //������ �����ϸ�
       * Connection successful ���
       */
      String raw = "";
      String other = "���";
      String message = "";

      textfield.setEditable(true); 					// textfield�� ���� �����ϰ� ��

      while (true) {
         switch (inctrl) {
         case 0:
            raw = (String) input.readObject();
            if (raw.indexOf("&nbsp;") > -1) {
               other = raw.split("&nbsp;")[0];
               message = raw.split("&nbsp;")[1];
            } else
               message = raw;
            if (selctrl(message) == 9)
               textarea.append("\n" + other + ">>> " + message);
            break;

         case 1:
            raw = (String) input.readObject();
            if (raw.indexOf("&nbsp;") > -1) {
               other = raw.split("&nbsp;")[0];
               message = raw.split("&nbsp;")[1];
            } else
               message = raw;

            if (keyset)
               InputKey();

            if (selctrl(message) == 9) {
               textarea.append("\n" + other + "(C)>>> " + message);
               try {
                  c = Cipher.getInstance("DES");
                  c.init(Cipher.DECRYPT_MODE, deskey);

                  BASE64Decoder decoder = new BASE64Decoder();

                  byte[] clearmessage = c.doFinal(decoder.decodeBuffer(message));

                  String cleartext = new String(clearmessage);

                  textarea.append("\n" + other + ">>> " + cleartext);
               } catch (Exception e) {
                  break;
               }
            }
            break;
         }
      }
   }

   private int selctrl(String message) {
      // ctrl�� ������ ctrl�� ����
      if (message.length() < 7)
         return 9;
      else if (message.equals("ctrl>>0")) {
         inctrl = 0;
         return 8; 								// ��Ʈ���� ��� 8�� ����
      } else if (message.equals("ctrl>>1")) {
         inctrl = 1;
         return 8;
      } else
         return 9; 								// ��Ʈ���� �ƴϰ� �Ϲ� �޼����϶�
   }

   private void closeConnection() {
      textfield.setEditable(false);

      try {
         output.close();
         input.close();
         s.close();
      } catch (IOException ioException) {
      }
   }

   private void sendData(String raw) {
      String message = "";
      String other = "";
      if (raw.indexOf("&nbsp;") > -1) {
         other = raw.split("&nbsp;")[0];
         message = raw.split("&nbsp;")[1];
      } else
         message = raw;
      try {
         switch (outctrl) {
         case 0:
            textarea.append("\n" + id + ">>> " + message);

            output.writeObject(raw);
            output.flush();
            break;
         case 1:
            try {
               textarea.append("\n" + id + ">>> " + message);

               c = Cipher.getInstance("DES");
               c.init(Cipher.ENCRYPT_MODE, deskey);

               byte[] cipheroutput = message.getBytes();
               byte[] ciphermessage = c.doFinal(cipheroutput);

               BASE64Encoder encoder = new BASE64Encoder();
               String ciphertext = encoder.encode(ciphermessage);

               textarea.append("\n" + id + "(C)>>> " + ciphertext);

               output.writeObject(other + "&nbsp;" + ciphertext);
               break;
            } catch (Exception e) {
               break;
            }
         }
      } catch (IOException ioe) {
         textarea.append("\nError writing object");
      }
   }

   @Override
   public void actionPerformed(ActionEvent e) {
      // TODO Auto-generated method stub
      if (e.getSource() == buttonFile) {
         if (jfc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            sendData(id + "&nbsp;" + jfc.getSelectedFile().getName() + " ������ �����մϴ�");
            textfield.setText("");

            try {
               FileInputStream fin = new FileInputStream(new File(jfc.getSelectedFile().toString()));

               byte[] buffer = new byte[1024];
               int data = 0;

               while (fin.read(buffer) > 0) {
                  data++;
               }

               fin.close();
               fin = new FileInputStream(jfc.getSelectedFile().toString());
               dout.writeInt(data);
               dout.writeUTF(jfc.getSelectedFile().getName());

               for (int len; data > 0; data--) {
                  len = fin.read(buffer);
                  s2.getOutputStream().write(buffer, 0, len);
               }

               byte[] bytes = Files.readAllBytes(Paths.get(jfc.getSelectedFile().toString()));
               signature_me.update(bytes);
               s2.getOutputStream().write(signature_me.sign(), 0, 46);
               
               sendData(id + "&nbsp;����: "+signature_me.sign());
               textfield.setText("");
            } catch (Exception ex) {
               ex.printStackTrace();
            }
         }
      }

   }
}