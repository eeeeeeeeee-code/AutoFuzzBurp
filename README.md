# UploadFuzzBurp

# 简介
  根据T3nk0的进行编写java版本的burp文件上传fuzz，优化了一些逻辑、以及一些绕过的功能点，感谢T3nk0的开源精神，以前也想写这种upload fuzz的工具，但是上传包多样就没有搞了，没想到还有这种方法，学习到了。

# 本人环境参考
> burp环境burpsuite 2025.2
>
> 工具环境：
>   java17编写
>   java17编译

# 功能介绍
<img width="896" alt="1743504399847" src="https://github.com/user-attachments/assets/a58be390-bb94-45f9-83aa-427019b99a27" />
 
  1. 后缀绕过
     
  2. 编码解码

  3. 协议绕过
     
  4. .......

# 使用方法
1.成功加载该插件

2.将需要fuzz的包，传送到Intruder中

3.设置这种部位为payload地址

<img width="993" alt="d7ddb43e46fa0a43360b7acd9741c31" src="https://github.com/user-attachments/assets/96c353f2-7e31-479e-aacc-40160ea18184" />

4.然后设置如下内容

<img width="962" alt="5bb289c7ea7184f13ce952090852061" src="https://github.com/user-attachments/assets/c7ff7855-ea31-4722-a64e-034760099bb2" />

# 参考项目
> https://github.com/T3nk0/Upload_Auto_Fuzz
>
> 以及一些文章，数量较多就不书列了。
