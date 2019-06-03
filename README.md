# Java-Chatting-Program

**It is using cryptography.**
- 대칭키: DES - 비밀 채팅 시 사용
- 공개키: RSA - 로그인 시 사용
- 압축: MD5 - 비밀번호 압축 시 사용, SHA1 - 파일 압축 시 사용
- 전자 서명: DSA - 파일 보낼 때 사용


#### 실행 영상

![Alt Text](https://github.com/LeeSongA/Security-Chatting-Program/blob/master/assets/%EC%8B%A4%ED%96%89%20%EC%98%81%EC%83%81.gif)


#### 실행 방법

- 실행 전 설치
  - `npm install expree`
  - `npm install mysql`
  - `npm install node-rsa`
  
- 실행 전 로그인 아이디, 비밀번호 데이터베이스 생성 (예시)
  - `create database project`
  - `mysql -u root -p`
  - `use project`
  - `create table user(id text, pwd text);`
  - `insert into user(id, pwd) values ('rest', '1234');`
  - 'insert into user(id, pwd) values ('test', '1234);`

- 실행 순서
  - LoginServer 폴더 `nope app`
  - JavaChatting 폴더 TCPstalks.java 실행
  - JavaChatting 폴더 TCPstalkc.java 실행
