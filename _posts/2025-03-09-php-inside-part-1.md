---
title: Inside PHP&colon; 배경지식 & 환경설정 (Part 1)
description: mainly php 7.4.33
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

## What is PHP-fpm?

## Let's install

사실 PHP 설치는 ~~매우~~ 귀찮습니다.

1. 버전관리
2. apache / nginx / php-fpm
3. `php.ini`{: .filepath } 설정

간소화 & 자동화하기 위해 linux(wsl)에서 설치를 진행하고, shell script를 직접 작성하겠습니다. 

(나중에 동아리 교육자료로 사용할 목적도 있기 때문에 이렇게 진행했습니다.)

## PHP Versions

### 1.x

### 5.x

- DB를 다양하게 사용할 수 있는 PDO(PHP Data Object) 개념 도입
- 네임스페이스, 익명함수
- UTF-8 기본 인코딩

### 6.x

버전 없음. 바로 7.0으로 바뀜

### 7.x

- AST Parser 적용 -> 메모리 사용량 1/5
- 7.4 프리로딩 도입 -> 최대성능 8% 향상
- 함수 매개변수 타입 지정 가능
- null 병합연산자(`??`) 지원

### 8.x

- JIT 도입, (Just-in-time), 예외처리 강화
- @연산자 삭제
- Null Safe 연산자 지원 (optional chaining)
- Enum 타입 추가
- 경량 스레딩 Fiber 추가

Reference[^2]

## Reference

[^1]: [https://ko.wikipedia.org/wiki/PHP](https://ko.wikipedia.org/wiki/PHP)
[^2]: [https://min-nine.tistory.com/entry/PHP-5-7-8-version-차이점-알아보기](https://min-nine.tistory.com/entry/PHP-5-7-8-version-차이점-알아보기)
