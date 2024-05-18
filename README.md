# CTF笔记
## 一.隐写技术
### 1.二维码
---
下载文件解压里面是二维码的图片<br>
![图片](./images/QRcode/QR.png)<br>
扫描出来<br>
![扫描](./images/QRcode/content.png)
写的secret is here,但不是flag,所以可能是用图片隐写技术隐藏了信息，放进kali用foremost看看
![foremost](./images/QRcode/fm.png)
foremost出来一个zip文件，里面有4number.txt，需要密码，发现也不是secret is here，看wp发现要爆破，4number代表4位数字
![爆破](./images/QRcode/bp.png)
把7639输进去打开txt
![答案](./images/QRcode/ans.png)
包上flag{}发现不对，把CTF换成flag就对了

### 2.大白
![图片](./images/dabai/dabai.png)
下载题目提供的文件，发现是一张大白的图片
![图片](./images/dabai/im.png)
根据题目提示“是不是屏幕太小了”推测图片大小被修改了，用010editor打开<br>
![图片](./images/dabai/err.png)
发现提示CRC Mismatch（最下面黄色条）<br>
***
**知识点：*对一张正常的图片，通过修改其宽度或者高度隐藏信息，使计算出的CRC校验码与原图的CRC校验码不一致；windows的图片查看器会忽略错误的CRC校验码，因此会显示图片，但此时的图片已经是修改过的，所以会有显示不全或扭曲等情况，借此可以隐藏信息。***<br>
***
![图片](./images/dabai/fix.png)
找到宽高位置，把高度256改为和宽度一样的679，保存图片后再次打开
![图片](./images/dabai/ans.png)
多出来一大块透明区域显然调多了（<br>
但无所谓答案已经出来了（<br>
把flag{He1l0_d4_ba1}交上去就好啦
## 二.流量分析与取证
### 1.大流量分析
#### (1)

![题干](./images/daliuliang/1T.png)
下载题目提供的流量包
![下载](./images/daliuliang/download.png)
确实大  好几个G（ <br/>
用小鲨鱼wireshark打开第一个文件<br/>
因为要查找黑客的ip，所以在统计中找到ipv4的数据，然后查看all adress
![查看](./images/daliuliang/ipv4.png)
把count从大到小排列，第一个占比57%的最活跃的ip大概率就是黑客的。
![找到](./images/daliuliang/values.png)
把flag{183.129.152.140}提交上去就ok了

#### (2)
![题干](./images/daliuliang/2T.png)
还是刚才那个流量包，用小鲨鱼打开<br/>
因为要查找黑客的邮箱，所以筛选出SMTP的协议
![smtp知识点](./images/daliuliang/smtp.png)
发现红圈里面有MAIL FROM一个邮箱，并且后面标注了Sender，推测这个就是黑客发来邮件的邮箱。
![筛选](./images/daliuliang/filter.png)
把flag{xsser@live.cn}提交上去就ok了

#### (3)
![题干](./images/daliuliang/3T.png)
看别人的wp似乎是道价值不大的烂题（<br/>
似乎直接搜索phpinfo逻辑不强？不懂 以后懂了再来补（
![wp1](./images/daliuliang/ans1.png)
![wp2](./images/daliuliang/ans2.png)

### 2.菜刀666
![题干](./images/caidao/T.png)
下载文件后解压，里面有.pcapng的文件，用小鲨鱼打开<br/>
中国菜刀是一个webshell管理工具，一般用POST进行上传，所以在小鲨鱼的过滤器中输入http.request.method==POST进行过滤
![过滤](./images/caidao/ws.png)
追踪一下tcp流，在第七个流中发现可疑数据
![TCP](./images/caidao/tcp.png)
以FFD8开头，去看一下结尾
![TCP](./images/caidao/tcp2.png)
是FFD9,说明这是一个jpg文件<br/>
用010editor分析，新建一个16进制文件
![010](./images/caidao/010.png)
把很长的16进制复制粘贴进来，一定要ctrl+shift+v，否则粘贴过来就不是要分析的16进制了
![010](./images/caidao/pst.png)
把文件导出，另存为jpg文件，打开图片
![jpg](./images/caidao/png.png)
交上去发现不是flag，所以推测这是某个压缩包的解压密码<br/>不过别人的wp也说能从TCP流里的这个看出来有加密的文件
![tcp9](./images/caidao/tcp9.png)
去kali用foremost分离一下看看<br/>
第一遍提醒我output文件夹有东西所以不行，就去清理了一下，然后就出来东西了
![fmst](./images/caidao/foremost.png)
去output文件夹里找一下分离出来的文件
![找到](./images/caidao/fd.png)
发现是一个需要解压密码的zip文件，把图片里的密码输进去
![解压](./images/caidao/flag.png)
把flag{3OpWdJ-JP6FzK-koCMAK-VkfWBq-75Un2z}交上去就ok了

