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
   private JTextField textfield; 					// JTextField 선언
   private JTextArea textarea; 						// JTextArea 선언
   private JRadioButton normaltext; 				// Plain Text 버튼 선언
   private JRadioButton ciphertext; 				// Cipher Text 버튼 선언
   private ButtonGroup radioGroup;
   private JButton buttonFile; 						// File Button 파일추가하기 버튼
   private JFileChooser jfc;
   private Cipher c;
   private ObjectOutputStream output;
   private ObjectInputStream input;
   private ServerSocket ss, ss2;
   private Socket s, s2;
   private DataOutputStream dout;
   private DataInputStream din;
   private Boolean keyset = true; 					// 키를 한번만 입력받게 하기 위한 변수
   private int inctrl; 								// 받은 메시지가 암호문인지 아닌지를 나타내는 컨트롤, 0:보통문, 1:암호문, 2:key
   private int outctrl = 0; 						// 보낼 메시지가 암호문인지 아닌지를 나타내는 컨트롤, 0:보통문, 1:암호문
   static public int destport = 5432;

   private SecretKeySpec deskey;
   private PrivateKey key_me;
   private PublicKey key_other, publicKey;
   private Signature signature_me, signature_other;

   public Server(String id) {
      super("TCPstalkServer"); 						// Server화면 타이틀 TCPstalkSever

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
                     sendData(id + "&nbsp;검증이 완료되었습니다");
                     textfield.setText("");
                  }else {
                     sendData(id + "&nbsp;검증에 실패! 파일이 삭제되었습니다.");
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
      panel = new JPanel(); 									// 라디오버튼과 키 입력이 들어갈 패널
      panel.setLayout(new FlowLayout());

      textfield = new JTextField(); 							// 키 입력할 필드
      textfield.setEditable(false); 							// 수정이 불가능하게 함. 연결되면 수정 가능
      textfield.addActionListener(new ActionListener() {
         public void actionPerformed(ActionEvent event) {
            sendData(id + "&nbsp;" + event.getActionCommand()); // 입력하면 메시지를 sendData메소드의 인자로 넘김
            textfield.setText(""); 								// textfield 초기화
         }
      });
      add(textfield, BorderLayout.NORTH); 						// textfield 위치 지정, 윈도우 북쪽에 추가

      textarea = new JTextArea();
      textarea.setEditable(false); 								// 출력되는 부분이기 때문에 수정이 불가능하게 함
      add(new JScrollPane(textarea), BorderLayout.CENTER); 		// textarea 위치 지정, 윈도우 중앙에 스크롤 붙여서 추가

      normaltext = new JRadioButton("Plain Text", true); 		// 보통문인지 선택하는 버튼
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
      jfc.setMultiSelectionEnabled(false); 					// 다중 선택 불가

      add(panel, BorderLayout.SOUTH);

      setSize(400, 500); 									// 윈도우 크기
      setVisible(true); 									// 화면에 보이게 함.
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

   public void runServer() { 								// 모든 실행되는 루틴이 있는 메소드
      try {
         ss = new ServerSocket(destport);

         while (true) {
            try {
               s = ss.accept(); 							// 클라이언트의 접속이 오기를 기다림.
               exchangeKey();
               getStream(); 								// 입출력 Stream을 얻는 메소드
               process(); 									// 얻어온 입출력 Stream으로 메세지를 보내고 받음.
            } catch (Exception e) {
               textarea.append("\nTerminated");
            } finally { 									// 마지막으로(끝날때) closeConnection() 실행
               closeConnection();
            }
         }
      } catch (IOException ioe) {
         textarea.append("no socket available");
      }
   }

   private void InputKey() {
      String Ikey = JOptionPane.showInputDialog("8글자  Key를 입력하세요");
      if (Ikey.length() == 8) {
         deskey = new SecretKeySpec(Ikey.getBytes(), "DES");
         keyset = false;
      } else {
         JOptionPane.showMessageDialog(null, "8글자를 입력해 주세요.");
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

   // 입출력 스트림을 얻어옴
   private void getStream() throws IOException {
      output.writeObject("DSA 공개키를 전달했습니다:" + publicKey.getEncoded());
      output.flush();
   }

   // 클라이언트와 연결된 후 처리(클라이언트가 서버에 보낸 메세지 처리)
   private void process() throws IOException, ClassNotFoundException {
      /*
       * String message = "Connection successful"; sendData(message); //연결이 성공하면
       * Connection successful 출력
       */
      String raw = "";
      String other = "운영자";
      String message = "";

      textfield.setEditable(true); 					// textfield를 수정 가능하게 함

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
      // ctrl이 왔을때 ctrl을 설정
      if (message.length() < 7)
         return 9;
      else if (message.equals("ctrl>>0")) {
         inctrl = 0;
         return 8; 								// 컨트롤인 경우 8을 리턴
      } else if (message.equals("ctrl>>1")) {
         inctrl = 1;
         return 8;
      } else
         return 9; 								// 컨트롤이 아니고 일반 메세지일때
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
            sendData(id + "&nbsp;" + jfc.getSelectedFile().getName() + " 파일을 전송합니다");
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
               
               sendData(id + "&nbsp;서명: "+signature_me.sign());
               textfield.setText("");
            } catch (Exception ex) {
               ex.printStackTrace();
            }
         }
      }

   }
}