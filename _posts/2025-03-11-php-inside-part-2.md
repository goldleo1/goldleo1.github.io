---
title: Inside PHP&colon; Type Juggling (Part 2)
description: php 7.4.33 ~ 8.4.4(latest)
author: goldleo1
date: 2025-03-11 00:00:00 +0800
categories: [cheatsheet]
tags: [web, php, inside php, Type Juggling]
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

## What is Type Juggling?

Type Juggling은 복수의 변수를 비교할 때 사용되는 Loose/Strict Comparison에 따라 개발자가 의도하지 않은 값으로 if 문 등을 통과할 수 있는 취약점을 의미합니다. [^1]

주로 PHP, JS등의 (웹)프로그래밍 언어에서 나타납니다.

```php
<?php
var_dump(1=='1');  // bool(true)
var_dump(1==='1'); // bool(false)
?>
```

문자 "1"이 숫자 1과 느슨한 비교를 수행하면서 숫자로 바뀌어 비교됩니다.

```php
<?php
var_dump("33e1" == "3300E-1");    // bool(true)
var_dump("15e0005" == "1500000"); // bool(true)
var_dump('1000e-1' == '100');     // bool(true)
var_dump("99e-2" == "0.99");      // bool(true)
var_dump('99e+2' == '9900')       // bool(true)
var_dump("1000e-1" < "1"); // bool(false)
var_dump("1000e-4" < "1"); // bool(true)
?>
```

대소비교연산자도 느슨한 비교를 함을 알 수 있다.

## So Why?

---

php의 변수들은 `_zval_struct`(zval)이라는 구조체로 구현되어있다.

{::options parse_block_html="true" /}

<details><summary markdown="span">zval 구현</summary>

```c
struct _zval_struct {
	zend_value        value;			/* value */
	union {
		struct {
			ZEND_ENDIAN_LOHI_3(
				zend_uchar    type,			/* active type */
				zend_uchar    type_flags,
				union {
					uint16_t  extra;        /* not further specified */
				} u)
		} v;
		uint32_t type_info;
	} u1;
	union {
		uint32_t     next;                 /* hash collision chain */
		uint32_t     cache_slot;           /* cache slot (for RECV_INIT) */
		uint32_t     opline_num;           /* opline number (for FAST_CALL) */
		uint32_t     lineno;               /* line number (for ast nodes) */
		uint32_t     num_args;             /* arguments number for EX(This) */
		uint32_t     fe_pos;               /* foreach position */
		uint32_t     fe_iter_idx;          /* foreach iterator index */
		uint32_t     access_flags;         /* class constant access flags */
		uint32_t     property_guard;       /* single property guard */
		uint32_t     constant_flags;       /* constant flags */
		uint32_t     extra;                /* not further specified */
	} u2;
};

typedef struct _zval_struct     zval;
```

</details>

{::options parse_block_html="false" /}

<br>

php의 연산자들은 [type:boolean,bitwise,shift,is]\_{op}\_function을 통해 계산됩니다.

```c
# define ZEND_API __attribute__ ((visibility("default")))

int ZEND_FASTCALL add_function(zval *result, zval *op1, zval *op2);                 /* + */
int ZEND_FASTCALL sub_function(zval *result, zval *op1, zval *op2);                 /* - */
int ZEND_FASTCALL mul_function(zval *result, zval *op1, zval *op2);                 /* * */
int ZEND_FASTCALL pow_function(zval *result, zval *op1, zval *op2);                 /* ** */
int ZEND_FASTCALL div_function(zval *result, zval *op1, zval *op2);                 /* / */
int ZEND_FASTCALL mod_function(zval *result, zval *op1, zval *op2);                 /* % */
int ZEND_FASTCALL boolean_xor_function(zval *result, zval *op1, zval *op2);         /* ^ */
int ZEND_FASTCALL boolean_not_function(zval *result, zval *op1);                    /* ! */
int ZEND_FASTCALL bitwise_not_function(zval *result, zval *op1);                    /* ~ */
int ZEND_FASTCALL bitwise_or_function(zval *result, zval *op1, zval *op2);          /* | */
int ZEND_FASTCALL bitwise_and_function(zval *result, zval *op1, zval *op2);         /* & */
int ZEND_FASTCALL bitwise_xor_function(zval *result, zval *op1, zval *op2);         /* ^ */
int ZEND_FASTCALL shift_left_function(zval *result, zval *op1, zval *op2);          /* << */
int ZEND_FASTCALL shift_right_function(zval *result, zval *op1, zval *op2);         /* >> */
int ZEND_FASTCALL concat_function(zval *result, zval *op1, zval *op2);              /* . */

zend_bool ZEND_FASTCALL zend_is_identical(zval *op1, zval *op2);                    /* === */

int ZEND_FASTCALL is_equal_function(zval *result, zval *op1, zval *op2);            /* == */
int ZEND_FASTCALL is_identical_function(zval *result, zval *op1, zval *op2);        /* === */
int ZEND_FASTCALL is_not_identical_function(zval *result, zval *op1, zval *op2);    /* !== */
int ZEND_FASTCALL is_not_equal_function(zval *result, zval *op1, zval *op2);        /* != */
int ZEND_FASTCALL is_smaller_function(zval *result, zval *op1, zval *op2);          /* < */
int ZEND_FASTCALL is_smaller_or_equal_function(zval *result, zval *op1, zval *op2); /* <= */


zend_bool ZEND_FASTCALL instanceof_function_ex(const zend_class_entry *instance_ce, const zend_class_entry *ce, zend_bool is_interface);
zend_bool ZEND_FASTCALL instanceof_function(const zend_class_entry *instance_ce, const zend_class_entry *ce);
```

(ZEND_API 생략)

`==`, `!=`, `<`, `>`, `<=`, `>=`와 같은 비교 연산자를 사용하면 compare_function함수를 호출한다.

```c
ZEND_API int ZEND_FASTCALL is_equal_function(zval *result, zval *op1, zval *op2)
{
	if (compare_function(result, op1, op2) == FAILURE) ...
}
```

```c
ZEND_API int ZEND_FASTCALL compare_function(zval *result, zval *op1, zval *op2)
{
	...
	switch (TYPE_PAIR(Z_TYPE_P(op1), Z_TYPE_P(op2))) {
		case TYPE_PAIR(IS_LONG, IS_LONG):
		case TYPE_PAIR(IS_DOUBLE, IS_LONG):
		case TYPE_PAIR(IS_LONG, IS_DOUBLE):
		case TYPE_PAIR(IS_DOUBLE, IS_DOUBLE):
		case TYPE_PAIR(IS_ARRAY, IS_ARRAY):
		case TYPE_PAIR(IS_STRING, IS_STRING):
			if (Z_STR_P(op1) == Z_STR_P(op2)) {
				ZVAL_LONG(result, 0);
				return SUCCESS;
			}
			ZVAL_LONG(result, zendi_smart_strcmp(Z_STR_P(op1), Z_STR_P(op2)));
			return SUCCESS;
		...
	}
	...
}
```

문자열과 문자열을 비교할 때는 `zendi_smart_strcmp()`를 호출함.

## Reference

[^1]: [https://www.hahwul.com/cullinan/type-juggling/](https://www.hahwul.com/cullinan/type-juggling/)
