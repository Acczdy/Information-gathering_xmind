# 外网信息收集

# 说明

近期看到别人公众号发了一个关于外网信息收集的思维导图，获取后的图片分辨率不太清晰，因此本地写出来，同时稍加改变增加了点自己收集的一些工具，

原文地址：

https://mp.weixin.qq.com/s/LOZlvQ0KyfiwbFjxDa6jcQ

此处附上svg版本，需要xmind联系：

![外网信息收集](./外网信息收集.svg)



## 企业资产信息

### 股权投资信息

- 天眼查
- 爱企查
- 钉钉庆典

### 公众号信息

- 企查查
- 搜狗搜索引擎
- 微信公众号

### 应用信息

- 天眼查
- 七麦数据
- 小蓝本
- 点点数据
- 豌豆荚

## 主域名信息

### ICP备案

- 备案信息查询

  - 站长工具ICP备案查询：https://icp.chinaz.com/
  - 工信部ICP备案：https://beian.miit.gov.cn/
  - 国外公开数据库：https://opencorporates.com/

- 未备案信息查询

  - 网络空间搜索引擎

    - 证书
    - IP

### whois

- 站长之家
- who.is
- IP138网站
- 狗狗查询：https://www.ggcx.com/
- ICANN LOOKUP：https://lookup.icann.org/zh

### IP反查

- 同IP网站查询：https://stool.chinaz.com/same
- DNSlytics：https://dnslytics.com/
- 搜索引擎

  - 网络空间搜索引擎

    - FOFA
    - Zoomeye
    - Shodan
    - Quake
    - Hunter
    - 零零信安

  - 普通搜索引擎

    - Google
    - Bing
    - Yandex：https://yandex.com/?
    - DuckDuckGoog：https://www.duckduckgoog.com/

### HOST碰撞

- 条件

  - IP
  - 域名

- 自动化

  - 灯塔
  - 水泽
  - HostScan：https://github.com/cckuailong/hostscan
  - Hosts_Scan：https://github.com/fofapro/Hosts_scan
  - Host_Scan：https://github.com/smxiazi/host_scan

### DNS共享记录

- 查询是否存在自建DNS服务器
- 查询：https://hackertarget.com/find-shared-dns-servers/

### Google语法

### 配置信息

- 策略文件

  - crossdomain.xml
  - sitemap

- 策略配置

  - CSP

### 众测

- 补天
- 漏洞银行
- 先知
- 火线
- 漏洞盒子
- CNVD

## 子域名信息

### 枚举爆破/查询

- 在线获取

  - 千寻：https://www.dnsscan.cn/dns.html
  - 站长之家-子域名查询：https://tool.chinaz.com/subdomain/?domain=
  - Google语法：site:xxx.com
  - DNSdumpster：https://dnsdumpster.com/
  - VirusTotal：https://www.virustotal.com/gui/home/search
  - https://phonebook.cz/

- 字典工具

  - 普通字典：字母数字组合
  - 常用词组
  - 其他字典

    - https://github.com/k8gege/PasswordDic
    - https://github.com/DNSPod/oh-my-free-data/tree/master/src

### DNS域传送

- nslookup

  - 查询nameserver

    - nslookup -type=ns knownsec.com 119.29.29.29 

  - 指定nameserver，列举域名信息

    - nslookup 
    - server f1g1ns1.dnspod.net 
    - ls knownsec.com

- dig

  - dig axfr @f1g1ns2.dnspod.net knownsec.com

- nmap

  - nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=knownsec.com -p 53 -Pn f1g1ns1.dnspod.net

- python

  - DNS库

### 证书透明度

证书透明度是一个开放体系，专门记录、审核并监控在互联网公开受信任的 TLS 证书。由于很多企业的域名都用了 https 协议，TLS证书里面一般包含域名信息，公司组织名称等，子域名中的证书信息一般情况也是一样的，可以通过证书透明度查询所有子域名

- 在线查询

  - https://crt.sh/
  - https://search.censys.io/
  - https://sslmate.com/certspotter/api/
  - https://developers.facebook.com/tools/ct

- 浏览器查询

### 公开数据集

- https://opendata.rapid7.com/

### 第三方组合服务

- virustotal：https://www.virustotal.com/gui/home/search
- https://hackertarget.com/
- https://searchdns.netcraft.com/
- https://dnsdumpster.com/
- https://www.threatminer.org/

### 工具

- https://github.com/FortyNorthSecurity/EyeWitness
- https://github.com/FeeiCN/ESD
- https://github.com/pingc0y/URLFinder
- https://github.com/p1g3/JSINFO-SCAN
- https://github.com/knownsec/ksubdomain
- https://github.com/projectdiscovery/subfinder
- https://github.com/shmilylty/OneForAll
- https://github.com/aboul3la/Sublist3r
- https://github.com/UnaPibaGeek/ctfr

### 搜索引擎

- Shodan
- FOFA
- Zoomeye
- Quake
- Hunter
- 谛听
- 知风
- 零零信安
- dnsdb

## IP信息

### 绕过CDN

- CDN判断

  - 多地ping
  - nslookup
  - 在线检测工具

    - https://www.cdnplanet.com/
    - https://tools.ipip.net/
    - https://www.whatsmydns.net/

- 获取真实IP

  - DNS历史绑定记录

    - https://www.dnsdb.io/zh-cn/
    - https://viewdns.info/
    - https://sitereport.netcraft.com/?url=
    - https://x.threatbook.com/
    - https://securitytrails.com/
    - https://site.ip138.com/

  - 网络空间搜索引擎

  - 子域名

  - 异地ping

  - SSL证书

  - CDN配置

  - 漏洞

    - SSRF等漏洞
    - 本身对外请求的业务
    - 异常信息
    - 调试信息

  - 邮件头

  - Hosts碰撞

  - 应用程序

    - 小程序
    - APP

  - F5 LTM解码法

    当服务器使用F5 LTM做负载均衡时，通过对set-cookie关键字的解码真实ip也可被获取，例如：Set-Cookie: BIGipServerpool_8.29_8030=487098378.24095.0000，先把第一小节的十进制数即487098378取出来，然后将其转为十六进制数1d08880a，接着从后至前，以此取四位数出来，也就是0a.88.08.1d，最后依次把他们转为十进制数10.136.8.29，也就是最后的真实ip。

  - 前端JS泄露IP

- 组织IP段

  - https://ipwhois.cnnic.net.cn/
  - https://apps.db.ripe.net/db-web-ui/query

- C段

  - msscan
  - Goby
  - 水泽
  - Fscan
  - 潮汐指纹：http://finger.tidesec.com/

- 旁站

- 端口

- IP定位

  - https://www.opengps.cn/
  - https://www.chaipip.com/

## 指纹信息

### CMS

- 特定文件的MD5
- 页面关键字
- 请求头信息关键字
- URL关键字
- 在线平台

  - http://finger.tidesec.net/
  - https://www.yunsee.cn/
  - https://whatcms.org/

- 工具

  - whatweb：https://github.com/urbanadventurer/WhatWeb
  - https://github.com/lcvvvv/kscan
  - https://github.com/Tuhinshubhra/CMSeeK
  - https://github.com/dionach/CMSmap
  - https://github.com/aedoo/ACMSDiscovery
  - https://github.com/TideSec/TideFinger
  - https://github.com/Lucifer1993/AngelSword
  - https://github.com/EdgeSecurityTeam/EHole

- 浏览器插件

  - https://www.wappalyzer.com/?utm_source=popup&utm_medium=extension&utm_campaign=wappalyzer

### WAF

### 组件信息

## 敏感信息

### 目录结构及敏感文件

- 工具

  - https://github.com/epi052/feroxbuster
  - https://github.com/maurosoria/dirsearch
  - https://github.com/H4ckForJob/dirmap

- 字典

  - https://github.com/TheKingOfDuck/fuzzDicts
  - https://github.com/gh0stkey/Web-Fuzzing-Box

### JS信息收集

- 手工
- 半自动

  - Passively Spider

- 自动化

  - https://github.com/Threezh1/JSFinder
  - https://github.com/p1g3/JSINFO-SCAN
  - https://github.com/pingc0y/URLFinder
  - https://github.com/gh0stkey/HaE

- 历史信息

  - https://github.com/tomnomnom/waybackurls
  - https://archive.org/

- 反混淆

  - https://github.com/beautify-web/js-beautify
  - https://github.com/lelinhtinh/de4js
  - https://github.com/winezer0/whatweb-plus

### Google Hacking

- intitle:	从网页标题中搜索指定的关键字
- inurl:		从url中搜索指定的关键字
- intext:		从网页中搜索指定的关键字
- filetype:	搜索指定的文件后缀
- site:		在某个指定的网站内搜索指定的内容
- link:		搜索与该链接有关的链接

### Github信息收集

- Github搜索语法

  - https://github.com/search/advanced
  - https://docs.github.com/zh/search-github/getting-started-with-searching-on-github/about-searching-on-github
  - https://github.com/obheda12/GitDorker

- 工具

  - https://github.com/obheda12/GitDorker
  - https://github.com/trufflesecurity/trufflehog

- 代码仓库在线搜索平台

  - https://pinatahub.incognita.tech
  - https://searchcode.com/
  - https://gitcode.net/explore

### 邮箱信息收集

- 邮箱入口

  - 端口
  - title
  - C段
  - 子域名
  - 搜索引擎
  - 网络空间搜索引擎

- 邮箱收集方法

  - 搜索引擎
  - 网络空间搜索引擎

    - Shodan
    - FOFA
    - Zoomeye
    - Quake
    - Hunter
    - 谛听
    - 知风
    - 零零信安

  - 在线收集平台

    - https://app.snov.io/
    - https://hunter.io/
    - https://phonebook.cz/
    - https://www.voilanorbert.com/
    - https://intelx.io/
    - http://www.skymem.com/

  - 爱企查、企查查、天眼查
  - 邮箱泄露信息查询

    - https://monitor.firefox.com/
    - https://haveibeenpwned.com/
    - https://www.dehashed.com/
    - https://ghostproject.fr/
    - https://checkusernames.com/
    - https://vigilante.pw/

  - 其他

    - https://app.apollo.io/
    - 社工库

  - 邮箱爆破字典

    - https://github.com/rootphantomer/Blasting_dictionary
    - https://github.com/TheKingOfDuck/fuzzDicts

### 网盘信息收集

- http://lzpanx.com/
- https://www.lingfengyun.com/
- https://www.dalipan.com/
- http://www.zhuzhupan.com/
- http://www.vpansou.com/

### 源码泄露

- https://github.com/lijiejie/GitHack
- https://github.com/kost/dvcs-ripper

### 其他信息收集

- https://github.com/projectdiscovery/httpx

## 其他信息

### APP

- 搜索引擎
- https://www.xiaolanben.com/pc
- https://www.qimai.cn/
- https://www.apple.com.cn/store
- https://www.diandian.com/
- https://www.wandoujia.com/
- 其他应用商城

### OSINT

- 情报资源

  - https://github.com/ffffffff0x/Digital-Privacy
  - http://www.dingba.top/
  - https://github.com/sinwindie/OSINT
  - https://inteltechniques.com/
  - https://osintframework.com/

- 情报工具

  - https://intelx.io/
  - https://github.com/woj-ciech/SocialPath
  - https://github.com/Greenwolf/social_mapper
  - https://github.com/bhavsec/reconspider

### 个人隐私信息

- 从邮箱查询

  - https://www.reg007.com/

- 从用户名查询

  - https://usersearch.org/
  - https://checkusernames.com/
  - https://whatsmyname.app/
  - https://namecheckup.com/
  - https://github.com/sherlock-project/sherlock

- 从IP查询

  - https://iknowwhatyoudownload.com/en/peer/

- 混合查询

  - https://usersearch.org/
  - https://github.com/n0tr00t/Sreg
  - https://data.humdata.org/
  - http://cha.yinhangkadata.com/
  - https://fapiao.youshang.com/
  - TG库

### 历史漏洞

- PeiQiWiki：https://github.com/PeiQi0/PeiQi-WIKI-Book
- Wooyun：https://wooyun.laolisafe.com/

### 蜜罐识别

- https://github.com/Ghr07h/Heimdallr

