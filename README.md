###########################
源项目为 freewaf 我只是做些许更改

###########################
nginx.conf 配置

    # lua_waf
    lua_shared_dict limit 50m;
    lua_shared_dict blackip 50m;
    lua_package_path "/usr/local/nginx/conf/waf/?.lua";
    init_by_lua_file  /usr/local/nginx/conf/waf/init.lua; 
    access_by_lua_file /usr/local/nginx/conf/waf/access.lua;

###########################
更新日志:
增加了whiteip cdip的功能,用以匹配ip段

    121.29.53.0/24
    120.55.146.0/24

增加config_set_ip_addr参数,用以指定获取源地址的方式:X_Forwarded_For X_real_ip[header] or ngx.var.remote_addr

    config_set_ip_addr = "X_Forwarded_For"

增加cc.rule -- 针对不同域名

    .*.abc.com|1/60   //匹配所有子域名
    oa.abc.com|60/60
    默认规则在config.lua里面配置[config_cc_rate]


增加black_ip_in_cache功能

    命中一次cc攻击后,拉入black_ip_in_cache,缓存600s[config_black_ip_cache]

参数rulematch

    rulematch(unescape(ARGS_DATA),rule,"jo") 修改
    为 rulematch(unescape(ARGS_DATA),rule,"joi")
    ----------------------------------
    i   大小写不敏感模式.
    防止参数攻击(select注入) 绕过waf:
    http://abc.com?app="sEleCt * fRom dual" 
    匹配模式不区分大小写

增加post_attack_check防止利用简单密码爆破,或者利用post参数列表插入非法参数

    测试方法:
         curl -H "Host:www.abc.com" -X POST -d "password=123456" http://www.abc.com/6666666666
         curl -H "Host:yum.ops.net"  -X POST -d "hj=select * FroM *"  http://127.0.0.1:8088/script/install-dev.sh

        <html>
        <head>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
        <meta http-equiv="Content-Language" content="zh-cn" />
        <title>网站防火墙</title>
        </head>
        <body>
        <h1 align="center"> 网站waf防火墙已拦截 </h1> 
        </body>
        </html


