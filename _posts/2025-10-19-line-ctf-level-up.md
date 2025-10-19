---
title: LINE CTF 2025 - Level-Up writeup
description: writeup for LINE CTF 2025's Level-Up challenge
author: goldleo1
date: 2025-10-19 12:00:00 +0800
categories: [ctf]
tags: [ctf, "2025"]
pin: false
---

## Review

We (Hypersonic team) finished LINE CTF 2025 in 10th place.

![alt text](/assets/img/2025-10-19/1.png)

Unfortunately, we didn't have enough time to fully engage with the CTF since we played two CTFs back-to-back.

But all web challenges were very great and fun to play.

I learned many new techniques, such as `crlf chars are replaced to underscore`.

## Level-Up

> This challenge is revenge of Another secure store note (LINE CTF 2023)

[Download Link](https://storage.googleapis.com/linectf_2025/Level-Up.zip)

### Analysis

Bot will register sites using `ADMIN_USERNAME` and `ADMIN_PASSWORD` with a random character suffix and write a post containing the flag.

```js
// Admin visiting your URL
async function visit(url) {
  console.log(`bot visits ${url}`);
  try {
    ...
    await page.goto(process.env.PAGE + '/register', { timeout: 3000, waitUntil: 'domcontentloaded' });
    await page.type('#username', process.env.ADMIN_USERNAME + '-' + rand());
    await page.type('#password', process.env.ADMIN_PASSWORD + '-' + rand());
    await page.click('#submit');
    await page.waitForNavigation();

    await page.evaluate(flag => {
      document.getElementById('content').value = flag;
      document.getElementById('form').submit();
    }, process.env.FLAG);
  }
  ...
}
```

```js
app.use((req, res, next) => {
  const nonce = rand();
  res.locals = { nonce };
  res.set('X-Frame-Options', 'SAMEORIGIN');
  res.set('Cross-Origin-Opener-Policy', 'same-origin');
  res.set('Cross-Origin-Resource-Policy', 'same-origin');
  res.set('Content-Security-Policy', `script-src 'nonce-${nonce}'`);
  next();
});

...

app.use((req, res, next) => {
  function clean(obj) {
    if (!obj) return;
    for (const [key] of Object.entries(obj)) {
      if (obj[key].includes('\'')) return next('Hack detected');
      obj[key] = Buffer.from(obj[key], 'utf-8').toString('ascii');
    }
  }
  clean(req.body);
  clean(req.query);
  clean(req.params);
  next();
});

...

app.use('/static', express.static(path.join(__dirname, 'static')))
app.use('/register', require('./routes/register'));
app.use('/bot', require('./routes/bot'));
app.use('/', require('./routes/index'));
```

`Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy` headers are set.

And every single quote is not allowed to use in `req.body`, `req.query`, `req.params`.

```js
// routes/register.js

route.get('/', (req, res) => {
  res.render('register');
})

route.post('/', async (req, res) => {
  let next = req.query.next || '/';
  if (req.user) {
    return res.redirect(`${next}?msg=Already logged in ${req.user.username}`);
  }
  const { username, password } = req.body;
  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') return res.redirect(`/register?msg=Invalid data`);
  let account = await get(dbAccount, username);
  if (account) account = JSON.parse(account);
  if (account && sha(password) !== account.password)
    return res.redirect(`/register?msg=Wrong password`);
  const id = rand();
  await dbSession.put(id, username);
  if (!account) {
    const csrf = rand();
    await dbAccount.put(username, JSON.stringify({
      csrf,
      username,
      password: sha(password),
      captcha: Math.floor(Math.random() * 9000 + 1000),
      posts: [],
    }));
  }
  res.cookie('id', id, {
    maxAge: 1000 * 60 * 60,
    httpOnly: true,
    secure: true,
    sameSite: 'none',
  })
  res.redirect(`${next}?msg=Successfully logged in`);
})
```

`/register` endpoint supports both register and sign-in.

We can set `req.query.next` to some url and this occurs open redirect. - ①

The `csrf` token logic is unsafe because the token is set once at registration and never renewed.

The code sets the `id` cookie with the `sameSite: 'none'` option, which allows cross-site POST requests (containing that cookie) to be sent to the server. - ②

By combining ① and ②, we are able to leak bot's username.

`dbAccount` and `get()` is implemented in `db.js`.

```js
// db.js

const path = require('path');
const { Level } = require('level');

const db = new Level(path.join(__dirname, 'database', process.env.NODE_ENV));

const dbPost = db.sublevel('posts');
const dbAccount = db.sublevel('account');
const dbSession = db.sublevel('session');

async function get(db, key) {
  for await (const key of db.keys()) {
    console.log(key);
  }

  try {
    return await db.get(key);
  } catch {
    return null;
  }
}
```

`db.sublevel()` has very interesting behavior.

`sublevel` sublevel appends a prefix in the format `![sublevel_name]!`.

For example, `dbAccount.put("username", {})` will saved as `!account!username={}` in real database file.
(`database/production/*.ldb`)

The `db` can access sublevels by adding the prefix directly. - `get(db, "!account!username")`

```js
// routes/index.js

route.use((req, res, next) => {
  if (!req.user) return res.redirect(`/register?msg=You need to login`);
  next();
});

route.get('/', async (req, res) => {
  const search = (req.query.s || '');
  const posts = [];
  for (let i = 0; i < req.user.posts.length; ++i) {
    const id = req.user.posts[i];
    const content = await get(db, id);
    if (content.toString().includes(search))
      posts.push(id);
  }
  res.render('index', { user: { ...req.user, posts } });
});

route.post('/', async (req, res) => {
  const { csrf, content } = req.body;
  if (csrf !== req.user.csrf) return res.redirect(`/?msg=Hack detected`);
  if (!content || typeof content !== 'string') return res.redirect(`/?msg=Invalid data`);
  const id = rand();
  await db.put(id, content);
  req.user.posts.push(id);
  console.log({ id, content });
  await dbAccount.put(req.user.username, JSON.stringify(req.user));
  res.redirect('/?msg=Successfully added new post');
});

route.get('/post/:id', async (req, res) => {
  const { id } = req.params;
  if (!id || typeof id !== 'string') return res.send('Invalid data');
  let content = (await get(db, id)) || '';
  if (content.length > 200) content = content.slice(0, 200) + '...';
  res.render('post', { content });
});
```

`/` endpoint checks whether the post is including `req.query.s` and render the page `index`.

When rendering the posts, `index.ejs` uses an iframe to load each post, so we can use `Frame Counting`, which uses `window.length` as an oracle for `XS-Leaks`.

But since COOP header is set, so we should add `<iframe src="ATTACKER_SERVER">` and use `window.top.length` to achieve Frame Counting.

```html
<!-- views/index.ejs -->
<script nonce="<%- nonce %>">
  window.user = <%- JSON.stringify(user) %>;
  window.onload = async () => {
    const search = new URLSearchParams(window.location.search);
    document.getElementById('search').value = search.get('search');
    document.getElementById('csrf').value = window.user.csrf;
    document.getElementById('username').textContent = window.user.username;
    const { posts } = window.user;
    const root = document.getElementById('root');
    for (let i = 0; i < posts.length; ++i) {
      const id = posts[i];
      const ifr = document.createElement('iframe');
      ifr.src = `/post/${id}`;
      root.appendChild(ifr);
    }
  }
</script>
```

To write post, we should send POST request to `/` with `csrf` token.

And in `/post/:id`, we are able to read post with only id. (no validation whether the post is user's)

Since `clean()` is sanitizing single quote, normal html injection is not available.

So use unicode (`ȧ><h1>123</h1>`) to inject HTML

```html
<meta charset="ascii">
<link rel="stylesheet" href="/static/post.css">
<input value='<%- content %>'>
```

Interestingly, the code uses `db` to read/write post instead of `dbPost`.

So we can leak bot's csrf token with leaked bot's username. (this is similar to common Redis vulnerabilities)

![/post/!account!username](/assets/img/2025-10-19/2.png)
_fun_

### Final Solution

1. Leak **bot's username** using open redirect

2. Leak csrf token using `!account![username]`

3. HTML Injection -> Frame Counting via window.top.length

### Exploit

[0xp1ain](https://x.com/0xp1ain) helped me to write exploit.

I will post better poc code later.