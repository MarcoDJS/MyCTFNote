# CUC CTF 寒假集训WP集
## 1.13 新手, MISC, 签到
### 一.404notfound
题目是一个图片，用010editor打开之后直接找到flag
![alt text](image.png)
### 二.What_1s_BASE
下载了一个txt文件
![alt text](image-1.png)
看起来像是base64，再加上题目what is base的提示，尝试base64解码
![alt text](image-2.png)
找到flag
### 三.hardMisc
题目是一个图片，用010editor打开之后翻到最后看到疑似base64编码
![alt text](image-3.png)
去解码得到flag
![alt text](image-4.png)
### 四.Hex？Hex！
下载了一个txt文件
![alt text](image-6.png)
根据编码特征+题目提示去hex解码
![alt text](image-5.png)
### 五.Is this only base?
txt文件
![alt text](image-7.png)
看起来是base64，但==不在最后，疑似是置换密码，提示了数字23，所以尝试n=23的栅栏解密
![alt text](image-9.png)
正好把==移到了最后，base64解码
![alt text](image-8.png)
我们看到ZQC明显是CTF的k=23的凯撒密码，解密后拿到flag
![alt text](image-10.png)
### 六.就当无事发生
![alt text](image-11.png)
题目中说数据没脱敏就发出去了，还好没有部署，看到网站使用github开发，说明存在git泄露，我们是可以通过github的commit记录找到敏感数据，即flag。
![alt text](image-12.png)
打开题目中的网站，在关于界面有开发者github的跳转页面，前往他的github
![alt text](image-13.png)
去他的Repositories中找到这个网站的仓库
![alt text](image-14.png)
看看他的Committ记录
![alt text](image-15.png)
由于这是2023年的LitCTF的题，所以这个Commit记录肯定是23年之前的，最后在图示commit记录中找到了flag
![alt text](image-16.png)
![alt text](image-17.png)