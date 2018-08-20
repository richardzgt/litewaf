############
nginx 软waf

增加了whiteip cdip的功能,用以匹配ip段
    121.29.53.0/24
    120.55.146.0/24

增加config_set_ip_addr参数,用以指定获取源地址的方式:X_Forwarded_For X_real_ip[header] or ngx.var.remote_addr
    config_set_ip_addr = "X_Forwarded_For"

增加cc.rule -- 针对不同域名
    .*.abc.com|1/60
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