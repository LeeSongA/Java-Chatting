const express = require('express');
const path = require('path');
const app = express();
const mysql = require('mysql');
const db = require('./config.json');
const crypto = require('crypto');
const NodeRSA = require('node-rsa');

var connection = mysql.createConnection({
  host     : db.host,
  user     : db.user,
  password : db.password,
  database : db.database
});
connection.connect();

/* 키 들, s는 서버(node.js) */
var publicKey_s;
var privateKey_s;
var key_s;

app.use(express.static(path.join(__dirname, '')));

/* 클라이언트가 로그인 요청할 때 */
app.get('/', (req, res) => {
   var id = req.query.id;

   /* '!' 문자를 '+' 문자로 치환, 이상하게 자바에서 node.js로 메시지를 전달할 때 '+' 문자가 전달 안됨        *
    * 그래서 자바에서 '+' 문자를 '!' 문자로 치환 후 전달 했고 받은 node.js는 '!' 문자를 '+' 문자로 다시 변경 */ 
   var encrypted_pwd = req.query.pwd.replace(/\!/gi, '+');                     
   var pwd;

   /* 암호화 된 비밀번호 출력 */
   console.log('받은 비밀번호(암호화된 비번): '+encrypted_pwd);

   /* 서버의 개인키로 암호화 된 비밀번호 해독 및 출력(출력된 형태는 MD5로 해쉬화 되있음) */
   pwd = key_s.decrypt(encrypted_pwd, 'utf-8');
   console.log('받은 비밀번호(개인키로 해독): '+pwd);

   console.log('\n사용자 "'+id+'"가 로그인을 시도 했습니다.');

   /* DB로 부터 비밀번호를 빼옴                                    *
      본래 DB에서 비밀번호 속성은 비밀번호 타입으로 저장해야하는데 *
      여기서는 Text나 varchar(숫자) 타입으로 저장했다고 가정       */
   connection.query("SELECT * from user where id='"+id+"'", function(err, rows, fields) {
      try{
         /* DB에 있는 비밀번호를 MD5를 통해 해쉬값으로 바꾼 후 클라이언트의 비밀번호와 비교, 그리고 값들이 같을 때 */
         if(crypto.createHash('md5').update(rows[0].pwd).digest("hex") == pwd){
            console.log('사용자 "'+rows[0].id+'"가 로그인 했습니다.\n');
            res.send("OK");
         }
         /* DB에 있는 비밀번호를 MD5를 통해 해쉬값으로 바꾼 후 클라이언트의 비밀번호와 비교, 그리고 값들이 다를 때 */
         else{
            console.log('사용자 "'+id+'"가 잘못된 비밀번호를 입력했습니다.');
            res.send("NO");
         }
      /* DB에 없는 아이디 일 경우 */
      }catch(exception){
         console.log('사용자 "'+id+'"가 잘못된 정보를 입력했습니다.');
         res.send("NO");
      }
   });
});

/* 공개 키 교환, "http://서버주소:8000/pub"에 접속하면 공개키를 보여줌*/
app.get('/pub', (req, res) => {   

   /* 서버의 공개키를 클라이언트에게 전달 */
   res.send(publicKey_s);
});

/* 로그인 서버 가동, 동시에 서버의 공개키와 개인키 생성 */ 
app.listen(8000, () => {
   process.stdout.write('\033c');
   console.log('Server is working on port 8000!');
   key_s = new NodeRSA({b: 1024});
   privateKey_s = key_s.exportKey("pkcs8-private");
   publicKey_s = key_s.exportKey("pkcs8-public-pem");
   console.log('생성된 개인키: '+privateKey_s.replace(/(-----END PRIVATE KEY-----)|(-----BEGIN PRIVATE KEY-----)/gi, ''));
   console.log('생성된 공개키: '+publicKey_s.replace(/(-----END PUBLIC KEY-----)|(-----BEGIN PUBLIC KEY-----)/gi, ''));
});