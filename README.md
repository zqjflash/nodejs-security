# XSS CSRF SQL注入，解决方案

### CSRF安全清单，nodejs安全处理

1. 目前存在的问题，CSRF需要构建(redis、memcache、dcache)等内存服务器，解决多进程，多服务的cookie，以及token的管理；

2. 使用g_tk的方式，进行csrf的防御。cookie进行token的转换，每次请求，都发送g_tk。

#### 一、XSS处理(使用xss组件)

>组件库引用：tnpm install --save xss 或npm install --save xss

1. XSS允许标签以data-开头的属性

```js
let str = '<div a="1" b="2" data-a="3" data-b="4">hello</div>';
let html = xss(str, {
    onIgnoreTagAttr: function(tag, name, value, iswhiteAttr) {
        if (name.substr(0, 5) === 'data-') {
            // 通过内置的escapeAttrValue函数对属性值进行转义
            return name + '="' + xss.escapeAttrValue(value) + '"';
        }
    }
});
```

2. XSS过滤特定标签开头的XSS注入

```js
let str = "<x><x-1>he<x-2 checked></x-2>wwww</x-1></a>";
let html = xss(str, {
    onIgnoreTag: function(tag, html, options) {
        if (tag.substr(0, 2) === 'x-') {
            // 不对其属性列表进行过滤
            return html;
        }
    }
});
```

3. 过滤所有非白名单标签的HTML，script标签比较特殊，需要过滤标签中间的内容

```js
let str = "<strong>hello</strong><script>alert(/xss/);</script>world";
let html = xss(str, {
    whiteList: [], // 白名单为空，表示过滤所有标签
    stripIgnoreTag: true, // 过滤所有非白名单标签的HTML
    stripIgnoreTagBody: ['script'] // script标签较特殊，需要过滤标签中间的内容
});
```
4. 过滤img标签

```js
let str = '<img src="img1">a<img src="img2">b';
let html = xss(str, {
    onTagAttr: function(tag, name, value, isWhiteAttr) {
        if (tag === 'img' && name === 'src') {
            // 使用内置的friendlyAttrValue函数对属性值进行转义，可将&lt;这类的实体标记转换成打印字符<
            list.push(xss.friendlyAttrValue(value));
        }
        // 不返回任何值，表示还是按照默认的方法处理
    }
})
```

#### 二、SQL注入测试用例,推荐第一种，统一管理。

>组件库引用：tnpm install --save mysql 或npm install --save mysql

1. 防注入方法一：使用connection.query的查询参数占位符符

```js
// `INSERT INTO user(id, name, age) VALUES(0, ?, ?)`
const mysql = require("mysql");
let sql = {
    insert: 'INSERT INTO user(id, name, age) VALUES(0, ?, ?)'
};
let db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '123456',
    database: 'test'
});

db.getConnection(function(err, connection) {
    connection.query(sql.insert, [name, age], function(err, result) {
        // ****
    });
});
```

2. 使用mysql.escape()对传入参数进行编码：

```js
const mysql = require("mysql");

let db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '123456',
    database: 'test'
});
let userId = 1;
let name = "test";

db.getConnection(function(err, connection) {
    connection.query("select * from users where id = " + connection.escape(userId) + ", name = " + connection.escape(name), function(err, result) {
        // ****
    });
});
```

3. 使用escapeId()编码SQL查询标识符，最常用于排序。

4. 使用mysql.format()转义参数：准备查询，该函数会选择合适的转义方法转义参数。

#### 三、CSRF的防护方案

##### 方案一（csurf组件）

>组件库引用：tnpm install --save csurf 或npm install --save csurf

1. 通过后台模板直出token；
2. 页面提交请求后，带回token，后台做校验；
3. 这里记得组件是不对cookie做检查的，开发者需要在接口中对cookie做校验，识别用户身份
4. 注意事项：服务必须是单进程，否则多进程的时候token存在下发不一致

```js

let parseForm = bodyParser.urlencoded({ extended: false });
let csrf = require('csurf');
let csrfProtection = csrf({ cookie: true });
// 以express框架为例
app.use("/csrf", parseForm, csrfProtection, function(req, res) {
    res.json({ csrfToken: req.csrfToken() })
});

```

##### 方案二（使用g_tk的方式）

>伪随机算法可以公开

1. 客户端和前端都采用一种伪随机的方式，进行cookie转token；
2. csrf的前提是没有xss，http劫持。如果有了xss和http劫持，那么csrf就没有意义；
3、在cookie安全的情况下，无法获取到cookie，也就是无法知道g_tk的值，因此就可以作为csrf防护。

```js
// 以某个用户身份作为示例
let gTkDemo = function(req, res) {
    let cookie = req.cookie['user'];
    let hash = 9999;
    for (let i = 0; i < cookie.length; i++) {
        hash += (hash << 5) + cookie.charAt(i).charCodeAt();
    }
    hash = hash & 0x7fffffff;
    res.render('g_tk', { g_tk: hash });
};

// 存在g_tk
let gTkHave = function(req, res) {
    let cookie = req.cookie['user'];
    let hash = 9999;
    for (let i = 0; i < cookie.length; i++) {
        hash += (hash << 5) + cookie.charAt(i).charCodeAt();
    }
    hash = hash & 0x7fffffff;
    let user_g_tk = req.query['g_tk'] || "";
    if (user_g_tk == hash) {
        res.json({
            data: {},
            status: {
                code: 200,
                msg: 'success'
            }
        });
    }
};

/**
* 不存在g_tk的情况，认为有问题，不是该用户过滤请求的数据
*/
let noGTkHave = function(req, res) {
    let cookie = req.cookie['user'];
    let hash = 9999;
    for (let i = 0; i < cookie.length; i++) {
        hash += (hash << 5) + cookie.charAt(i).charCodeAt();
    }
    hash = hash & 0x7fffffff;
    let user_g_tk = req.query['g_tk'] || "";
    if (user_g_tk == hash) {
        res.json({
            data: {},
            status: {
                code: 200,
                msg: 'success'
            }
        });
    }
};

```

### 附录

1. [Node.js安全清单](https://segmentfault.com/a/1190000003860400#articleHeader20)

2. [js-xss组件](https://github.com/leizongmin/js-xss)

3. [mysql防注入](http://www.dengzhr.com/node-js/877)

4. [QQ空间的g_tk算法简述](http://jtwo.me/g_tk-algorithm-of-qzone)
