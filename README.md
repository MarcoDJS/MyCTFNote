# CUCCTF训练2025 [03-05 ~ 03-11]
## 本期主题关键词
图片隐写，音视频隐写，流量分析，电子取证，AI
## 本周题目

- [x] [SWPU 2019]神奇的二维码 https://www.nssctf.cn/problem/39

- [ ] [ccbciscn 2024]WinFT_1 https://github.com/CTF-Archives/2024-ccbciscn/tree/main 

- [ ] [ccbciscn 2024]WinFT_2 https://github.com/CTF-Archives/2024-ccbciscn/tree/main

- [ ] [ccbciscn 2024]WinFT_5 https://github.com/CTF-Archives/2024-ccbciscn/tree/main
### 神奇的二维码
图片binwalk出来一堆东西
![alt text](image.png)
![alt text](image-1.png)
encode.txt里明显是base64
![alt text](image-2.png)
解密得到asdfghjkl1234567890，发现这个是看看flag的解压密码，里面就是图片，已经被walk出来了
flag.doc里有很长的base64
![alt text](image-3.png)
解码多次后得到comEON_YOuAreSOSoS0great，发现这个是18394的解压密码，解压出MP3文件
![alt text](image-4.png)
听到摩斯密码
用audacity打开查看
![alt text](image-5.png)
破译得到morseisveryveryeasy，包上NSSCTF{}提交
注意：摩斯密码不区分大小写，提交flag时需多尝试不同大小写
