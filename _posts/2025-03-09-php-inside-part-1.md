---
title: Inside PHP&colon; 배경지식 & 환경설정 (Part 1)
description: php 7.4.33 ~ 8.4.4(latest)
author: goldleo1
date: 2025-03-09 00:00:00 +0800
categories: [cheatsheet]
tags: [web, php, rce, inside php]
pin: false
draft: true
---

## Before You Begin to Read

이 글은 해킹을 공부하기 위해 작성하는 글로 아직 미흡한 부분이 많이 존재합니다.

만약 개념이나 설명 등에서 오류를 발견하셨다면 저에게 알려주시면 기쁘게 피드백 받도록 하겠습니다.

`Inside PHP` 시리즈는 munsiwoo님이 2019 Codegate에서 발표하신 [PHP Trick Trip](https://github.com/munsiwoo/PHP-Trick-Trip)의 개념들을 바탕으로 시작하여 
Zend Engine의 동작부터 php와 apache의 misconfigure에서 발생하는 취약점, php에서만 발생하는 특별한 trick 등을 
CTF & Real-World를 통한 Case-Study를 통해 알아보며 다양한 내용들을 다룰(공부할) 예정입니다.

> 읽어주셔서 감사합니다!

## What is PHP?

PHP(PHP: Hypertext Preprocessor)는 범용 프로그래밍 언어다.
동적 웹 페이지를 만들기 위해 설계되었으며 PHP로 작성된 코드를 PHP 엔진에서 html 파일과 같이 처리하여 작성자가 원하는 웹 페이지를 생성한다.

2015년 PHP 7.0이후에는 PHP 코드와 HTML을 별도 파일로 분리하여 작성하는 경우가 일반적이며, PHP 또한 웹서버가 아닌 php-fpm(PHP FastCGI Process Manager)을 통해 실행하는 경우가 많다.
[^1]

![alt text](assets/img/2025-03-09 01-49-44.png)

[tiobe.com](tiobe.com)에 따르면 php는 2000년대 초반에 많은 인기를 끌다가 이후 점점 인기가 하락하고 있는 언어이다.

~~(태어나기 전이라 사실 잘 모르겠다)~~

프론트와 백을 하나의 파일에서 처리할 수 있다는 것이 장점이자 단점으로 생각되는 것 같다.

사용률이 줄고는 있지만 프론트엔드 파일의 확장자를 `.php`로만 바꾸고 간단한 백엔드 코드를 작성할 수 있기 때문에 작은 프로젝트에도 많이 사용된다.

php를 사용하는 프로젝트는 [워드프레스](https://ko.wikipedia.org/wiki/워드프레스), [미디어위키](https://ko.wikipedia.org/wiki/미디어위키) 등이 있고, 국내에는 [그누보드](https://ko.wikipedia.org/wiki/그누보드) 등이 있다.

## How to use PHP?

---

ChatGPT선생님의 도움을 통해 한번 알아보았다.

| 항목          | Apache | Nginx | CGI | FastCGI | PHP-FPM |
|--------------|--------|-------|-----|---------|---------|
| **역할**      | 웹 서버 | 웹 서버 | PHP 실행 방식 | PHP 실행 방식 | PHP 실행 방식 |
| **PHP 실행 지원** | mod_php, CGI, FastCGI, PHP-FPM | PHP-FPM 필요 | 요청마다 새로운 프로세스 생성 | 프로세스를 유지하며 여러 요청 처리 | FastCGI 기반으로 성능 최적화 |
| **성능** | 보통 (멀티 프로세스 기반) | 높음 (비동기 처리) | 낮음 (매 요청마다 프로세스 생성) | 높음 (프로세스 재사용) | 매우 높음 (FastCGI 최적화) |
| **동시 요청 처리** | 상대적으로 낮음 | 매우 높음 | 낮음 | 높음 | 매우 높음 |
| **리소스 사용량** | 높음 (프로세스 개별 실행) | 낮음 (비동기 이벤트 기반) | 매우 높음 | 낮음 | 낮음 |
| **설정 유연성** | 높음 (.htaccess 지원) | 낮음 (.htaccess 없음) | 낮음 | 보통 | 보통 |
| **사용 사례** | 전통적인 웹 서버, `.htaccess` 필요할 때 | 고성능, 정적 콘텐츠 & PHP-FPM 조합 | 초창기 PHP 실행 방식 | FastCGI 방식으로 성능 개선 | PHP 실행 최적화 (Nginx 기본 방식) |

- **Apache**: 오래된 전통적인 웹 서버, `.htaccess` 지원, mod_php 사용 가능.
- **Nginx**: 가볍고 빠른 웹 서버, PHP 실행을 위해 PHP-FPM 필요.
- **CGI**: 요청마다 새로운 프로세스를 실행하는 방식, 성능이 낮음.
- **FastCGI**: CGI의 단점을 보완하여 프로세스를 유지하며 요청을 처리하는 방식.
- **PHP-FPM**: FastCGI 기반으로 최적화된 PHP 실행 방식, **Nginx & Apache**에서 모두 사용 가능.

### ✅ 결론
- **높은 동시 요청 처리 성능이 필요한 경우** → `Nginx + PHP-FPM 조합 추천`  
- **.htaccess 사용이 필요하고, 기존 Apache 환경을 유지하려면** → `Apache + PHP-FPM 추천`  
- **가장 간단하게 PHP 실행을 원한다면** → `Apache + mod_php 가능하지만 리소스 사용량 높음`

[From ChatGPT](https://chatgpt.com/share/67cd8cf1-0284-800d-81ee-3179eb91894a)

## PHP Versions

버전별 핵심 업데이트 사안 및 CTF관점에서 자주 나오는 취약점(trick)을 정리해보았습니다.

### 5.x

- DB를 다양하게 사용할 수 있는 PDO(PHP Data Object) 개념 도입
- 네임스페이스, 익명함수
- UTF-8 기본 인코딩

#### ✅ In the context of CTF
- open_basedir trick?

### 6.x

버전 없음. 바로 7.0으로 바뀜

### 7.x

- AST Parser 적용 -> 메모리 사용량 1/5
- 7.4 프리로딩 도입 -> 최대성능 8% 향상
- 함수 매개변수 타입 지정 가능
- null 병합연산자(`??`) 지원

#### ✅ In the context of CTF
- very hot 🔥
- $_GET[] trick
- nginx + php lfi to rce
- phar deserialization
- soap ssrf


### 8.x

- JIT 도입, (Just-in-time), 예외처리 강화
- @연산자 삭제
- Null Safe 연산자 지원 (optional chaining)
- Enum 타입 추가
- 경량 스레딩 Fiber 추가


#### ✅ In the context of CTF
- php-cgi cve

## Let's install

사실 PHP 설치는 ~~매우~~ 귀찮습니다.

1. 버전관리
2. apache \| nginx \| php-fpm \| cgi \| mod_php
3. `php.ini`{: .filepath } 설정

간소화 & 자동화하기 위해 linux(wsl)에서 docker를 활용하여 설치를 진행했습니다.

> `<embed>`를 사용해서 임시방편으로 써놨는데 나중에 수정하겠습니다.

<embed src="/assets/code/inside-php-part-1/" type="text/html" width="800" height="600">

> 몰랐는데 로컬(WEBrick, 루비)에서만 작동해서 나중에 하겠습니다.

Reference[^2]

## Let's download source code

```sh
sudo apt update && sudo apt upgrade -y
sudo apt install -y gcc g++ libxml2 libxml2-dev

wget https://museum.php.net/php7/php-7.4.33.tar.gz
tar -xvf php-7.4.33.tar.gz 1> /dev/null

cd php-7.4.33/
./configure --disable-all --enable-debug
make
make install
```

최신 버전(8.4.4, latest)까지는 업데이트되어있지 않지만 편하게 되어있습니다.

## Reference

[^1]: [https://ko.wikipedia.org/wiki/PHP](https://ko.wikipedia.org/wiki/PHP)
[^2]: [https://min-nine.tistory.com/entry/PHP-5-7-8-version-차이점-알아보기](https://min-nine.tistory.com/entry/PHP-5-7-8-version-차이점-알아보기)
