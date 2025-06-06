# AutoBurpFuzz

# 简介
1.tls and http 浏览器指纹绕过
2.被动指纹扫描
3.文件上传 Intruder fuzz
4.手机号 Intruder fuzz

# 本人环境参考
> burp环境burpsuite 2025.2
>
> 工具环境：
>   java17编写
>   java17编译

# tls指纹绕过使用方法
1.将需要绕过的域名，直接添加既可

![image](https://github.com/user-attachments/assets/a02d0a3d-8800-4ae3-9810-72d569858ca8)


# upload_fuzz使用方法
1.成功加载该插件,smb_fuzz和下面同理

2.将需要fuzz的包，传送到Intruder中

3.设置这种部位为payload地址

<img width="993" alt="d7ddb43e46fa0a43360b7acd9741c31" src="https://github.com/user-attachments/assets/96c353f2-7e31-479e-aacc-40160ea18184" />

4.然后设置如下内容

<img width="962" alt="5bb289c7ea7184f13ce952090852061" src="https://github.com/user-attachments/assets/c7ff7855-ea31-4722-a64e-034760099bb2" />



# 参考项目
> https://github.com/T3nk0/Upload_Auto_Fuzz
>
> https://github.com/shuanx/BurpFingerPrint
>
> https://github.com/yuziiiiiiiiii/SMS_Bomb_Fuzzer
>
> https://github.com/PortSwigger/bypass-bot-detection
