---
title: Mysql String Bypass
description: Mysql Tricks about String
author: goldleo1
date: 2024-10-17 12:00:00 +0800
categories: [hacking]
tags: [mysql]
pin: false
---

> 이 글은 mysql 8.0을 기준으로 작성됨 (2024.10.17)

---

## VARCHAR과 CHAR의 차이

[개발 관점에서의 VARCHAR와 CHAR의 차이](https://medium.com/daangn/varchar-vs-text-230a718a22a1)

<span style="color: grey;">이 글에서는 주가 아니므로 넘어간다.<span>

- CHAR는 **고정길이**를 가진 문자열로, 테이블에 정의된 길이로 고정되며 남는 공간은 공백으로 채워서 저장된다.

- VARCHAR는 **가변길이**를 가진 문자열로, 문자열의 길이를 함께 저장한다.

- CHAR는 뒤쪽의 공백을 모두 빼고 출력(비교)한다. 그래서 `'admin     	'`과 `'admin'`을 넣었을 때 컬럼에는 같은 값이 들어간다.

- CHAR, VARCHAR, TEXT 모두 기본적으로 대소문자 구분을 하지 않는다. (BINARY를 통해 구분)

```sql
'admin   ' = 'admin' # true (CHAR)
'admin   ' = 'admin' # false (VARCHAR)
```

---

## mysql이 문자열을 파싱하는 방법

> **php**, **nodejs**, **python등에서** 문자열을 처리하는 방식과 **mysql**에서 처리하는 방식이 달라 발생한다.

입력값 -> 결과값(데이터)

따옴표(')와 쌍따옴표(")는 대부분의 상황에서 서로를 바꾼 결과가 동일하다.

```
"test\test" -> test	    test
"test\Test" -> testTest
"asdf'asdf" -> asdf'asdf
'qwer''qwer' -> qwer'qwer
'asdf\Xadsf' -> asdfXasdf ! 메인 아이디어
```

> 이스케이프 문자인 백슬래시(\\) 뒤에서는 지정된 문자만 이스케이프 시퀀스로 처리된다. (Case-Sensitive)
>
> - 지정된 문자들 : \0, \\', \\", \b, \n, \r, \t, \Z(Ctrl+Z), \\\\, \\%, \\\_

---

## Character Set Trick

{::options parse_block_html="true" /}

<details>
<summary markdown="span">배경지식(charset, encoding)</summary>

> **Character set** : 사용하는 언어를 표현하기 위한 문자들의 집합을 의미.
>
> **Encoding** : Character Set을 컴퓨터가 이해할 수 있는 바이트와 매핑해 주는 것

- 유니코드(Unicode) : 전 세계의 모든 문자를 다루도록 설계된 표준 문자 전산 처리 방식

- **utf8** 인코딩 : 가변 길이 유니코드 인코딩 (U+000000~U+10FFFF까지 할당됨)

> 구조 : 표식비트(0, 110, 1110, 11110) + 데이터 비트

1. 0~127은 아스키 코드와 완벽한 호환성을 지닌다.

2. 추가예정

```sql
SHOW character set; # 사용 가능한 캐릭터셋 확인
--> latin1(default), euckr, utf8, utf8mb4 (2byte 이상)

status
/*
Server characterset: latin1
Db characterset: latin1
Client characterset: utf8
Conn. characterset: utf8
*/

CREATE DATABASE `utf8db` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;
ALTER DATABASE `utf8db` DEFAULT CHARACTER SET utf8;
SELECT schema_name, default_character_set_name FROM information_schema.schemata;

CREATE TABLE `utf8table` (id int , name varchar(10)) DEFAULT CHARSET=utf8 ;
SELECT table_name , table_collation FROM information_schema.tables WHERE table_schema = 'information_schema' AND table_name = 'utf8table';

set names euckr; # 세션레벨(=임시)로 변경
```

Reference

[UTF-8](https://ko.wikipedia.org/wiki/UTF-8)

[MySQL character set - 티스토리](https://bstar36.tistory.com/307)

[Document](https://dev.mysql.com/doc/refman/8.4/en/charset.html)

</details>

{::options parse_block_html="false" /}

### 1. UTF8(UTF8MB4) -> latin1 변환시의 깨짐

```php
# index.php
<?php
$conn = new mysqli("localhost","root","root","user");
$id = addslashes($_GET['id']) ?? ''; # admin%c2 로 우회가능
if($id === 'admin') exit("no admin");

$conn->query("set names utf8");
$result= $conn->query("select * from user where id='$id'");
while($row = $result->fetch_array()) {
	var_dump($row);
}
if($row['id'] === 'admin') {
    solve();
}
?>
```

이 현상을 이해하기 위해서는 mysql 의 Character Set 변환 메커니즘을 알아야한다.

mysql 에서는 시스템 변수인 character_set_client, character_set_connection, character_set_server 의 값을 각각 참조하여 다음의 프로세스를 거친다.

(i) 요청이 들어올 경우 character_set_client를 character_set_connection로 변환

(ii) character_set_connection 를 내부 인코딩(internal charset)으로 변환한다.
이 때 내부 인코딩 변환 시에는 필드, 테이블, DB 의 character set, character_set_server를 차례대로 시도한다. 테이블의 인코딩 설정은 필드의 설정에 상속되어 결국 필드 설정을 따르는 경우가 대다수다.

(iii) 결과를 character_set_results 를 참조하여 변환한 뒤 사용자에게 돌려준다.

​
이 때 서버의 기본 character_set 설정을 유지하였을 경우 set names utf8 을 하였을 때 character_set_client, character_set_connection 는 utf8 이 되지만 create table 에서 별도의 character set 을 지정하지 않았을 경우 internal charset 은 latin1 이 기본값이다.

즉, **utf8 - utf8 - latin1** 의 변환 과정을 거치며 이 과정에서 깨진 utf8 문자가 유실되는 것이다.​

RFC 3629 와 UTF8 의 구조에 따르면 UTF8 의 첫번째 바이트로 올 수 있는 범위는 **00-7F**, **C2-F4** 이다.

이 때 F0~F4 는 4 바이트 문자를 표현할 때 쓰이는 바이트로 utf8mb4 에서 인식한다. (utf8에서는 X)

또한, 00-7F 는 아스키 범위로 아스키는 한바이트 이기 때문에 깨질 수 없다.

```py
from pwn import *

p = process(['sudo', 'mysql'])

p.sendline("set names utf8;")
for i in range(0xc0,  0xf6):
    p.sendline(f"select convert('admin{chr(i)}' using latin1)='admin';")
p.interactive()
# 0xC2 ~ 0xEF에서 성립.
# UTF8MB4라면 0xC2 ~ 0xF4
```

**How to fix**

create table 시 character set 을 명시적으로 지정한다.

**Reference**

[Reference](https://blog.naver.com/dmbs335/221752512984)
[RFC 3629-UTF-8](https://datatracker.ietf.org/doc/html/rfc3629)
[CTF - chinese](https://paper.seebug.org/267/)

### 2. mysql collation trick ('a' == 'ã')

<details>
<summary markdown="span">배경지식</summary>

[단어장] collation : 정보 수집 분석

collation : 정해진 인코딩을 바탕으로 글자끼리 어떻게 비교할지 정의해 놓은 규칙

```
utf8mb4_0900_ai_ci # 기본 collation
- utf8mb4 : 캐릭터셋 매핑 (mb4 : 4byte 지원), 바로 이어서 지역 및 언어를 나타내는 단어로 세분화되기도 함
- 0900 : version-9.0.0 UCA 표준을 따름
- ai : accent insensitive (이전버전에서는 악센트 구분이 안되었으며 MySQL 8.0 부터 추가됨)
- ci : case insensitive (대소문자 구분하지 않음)
```

```sql
select 'ก์' COLLATE 'utf8mb4_general_ci'; # COLLATE 키워드를 통해 collation을 지정할 수 있다.
```

</details>

mysql 8.0부터 기본 collation 이 'utfmb4_0900_ai_ci'이다.

이 말은 accent와 case를 구분하지 않고, 아래와 같은 예시로 쉽게 확인할 수 있다.

```sql
SELECT 'ก' = 'ก์'; -- 1
select 'ก' = 'ก์' COLLATE 'utf8mb4_general_ci'; -- 0
```

**Reference**

[naver blog](https://blog.naver.com/sory1008/223071678680)
[mysql v6.0.0의 collation chart](https://collation-charts.org/mysql60/)
[mysql의 대표 collation 비교하기](https://juneyr.dev/mysql-collation)
[Typing accent marks](https://ipa.typeit.org/)

---

## Difference in Length

utf8의 코드 포인트는 1\~4바이트, utf16은 2\~4바이트이다.

이때 코드포인트를 표현하는데 필요한 최소 바이트 수를 `code unit`이라고 한다.

정확한 해석도 아니고, 그때그때 상황봐서 사용해야 한다.

**언어별 length 동작 방식**

```
# 🤦‍♀️ = 0xD83E 0xDD26 0x200D 0x2640 0xFE0F (in UTF-16)

JAVA - 5(13) - 내부적으로 utf16사용 (test안함)

Javscript - 5 - utf8 사용?

Python - 4-  utf8 사용 - 3바이트씩 묶음
a= "🤦‍♀️"
print(a.encode('utf-8'), len(a))
print(list(a))
# b'\xf0\x9f\xa4\xa6\xe2\x80\x8d\xe2\x99\x80\xef\xb8\x8f' 4
# ['🤦', '\u200d', '♀', '️'] - 손 짚은 이모티콘 + 여자

MYSQL (character set에 종속)
SELECT LENGTH("🤦‍♀️"); -- 13, UTF-8로 바꿨을 때 bytes의 길이
SELECT CHAR_LENGTH("🤦‍♀️"); -- 4, 실제 문자수(3바이트씩 묶음)
```

**Reference**
[글자 수세기](https://juneyr.dev/counting-character)

---

###### [Main Reference](https://blog.naver.com/dmbs335/221752512984)
