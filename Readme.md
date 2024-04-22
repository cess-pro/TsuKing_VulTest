[Author.go](Author.go) ：Golang编写的权威侧分析程序；

    输出请求、及回复日志，输出抓取到的RD请求中的解析器IP地址

    需要修改网卡、Mac地址、网关Mac地址等信息，在文件头部

[Prob.py](Prob.py) ：Python编写的请求侧分析程序

    发送RD请求

    本地通过连续请求的耗时判断是否有负缓存

    程序输入：
        `The file of target IPs` : 需要测试的解析器列表文本文件（最好提供完整路径），每行一个，IPv4 Only

        `Base domain`：测试用域名的基础域名：e.g. Base domain为`tsukingtest.dnssec.top`，程序会生成测试用域名分别为：xxx-xxx.rdtest.tsukingtest.dnssec.top; xxx-xxx.basetest.tsukingtest.dnssec.top; xxx-xxx.negtest.tsukingtest.dnssec.top

使用如下命令生成可执行文件（dist目录下）：
```
pyinstaller --onefile --clean 0.Prob.py
```




# 判定标准

## RD

发送不带有RD标识的请求，在权威侧判断是否收到该查询

## 负缓存

- 方案一(目前方案)：基础判断是否对ServerFailure、timeout进行缓存；

    能有缓解，不能阻断攻击

- 方案二：判断是否对“已经失效的权威”进行缓存，即对于不同的恶意“子域名”均不再查询；

    能够阻断攻击

代码实现在于Prob文件中，负缓存测试时，是否请求不同的子域名。

判断标准是连续请求的耗时的**中位数**，或许可以换其他方式

