--WAF Action
require 'config'
require 'lib'

--args
local rulematch = ngx.re.find
local unescape = ngx.unescape_uri


--Get whiteIP by iputils
function white_ip_check()
    if config_white_ip_check == "on" then
        local iputils = require("iputils")
        -- iputils.enable_lrucache()
        local IP_WHITE_RULE = get_rule('whiteip.rule')
        local CLIENT_IP = get_client_ip()
        whitelist = iputils.parse_cidrs(IP_WHITE_RULE)
        if whitelist ~= nil then
        	if  iputils.ip_in_cidrs(CLIENT_IP, whitelist) then
                -- log_record('White_IP',ngx.var.request_uri,CLIENT_IP,"_")
            	return true
        	end
        end
    end
end


--allow white ip
function white_ip_check_old()
     if config_white_ip_check == "on" then
        local IP_WHITE_RULE = get_rule('whiteip.rule')
        local WHITE_IP = get_client_ip()
        if IP_WHITE_RULE ~= nil then
            for _,rule in pairs(IP_WHITE_RULE) do
                if rule ~= "" and rulematch(WHITE_IP,rule,"jo") then
                    log_record('White_IP',ngx.var.request_uri,"_","_")
                    return true
                end
            end
        end
    end
end

--deny black ip
function black_ip_check()
     if config_black_ip_check == "on" then
        local IP_BLACK_RULE = get_rule('blackip.rule')
        local BLACK_IP = get_client_ip()
        local blackip = ngx.shared.blackip
        local req,_ = blackip:get(BLACK_IP)
        if req then
            log_record('Blackip_in_cache',ngx.var.request_uri,"_","_")
            ngx.exit(403)
        end
        if IP_BLACK_RULE ~= nil then
            for _,rule in pairs(IP_BLACK_RULE) do
                if rule ~= "" and rulematch(BLACK_IP,rule,"jo") then
                    if config_waf_enable == "on" then
                        log_record('BlackList_IP',ngx.var.request_uri,"_","_")
                        ngx.exit(403)
                        return true
                    end
                end
            end
        end
    end
end

--allow white url
function white_url_check()
    if config_white_url_check == "on" then
        local URL_WHITE_RULES = get_rule('whiteurl.rule')
        local REQ_URI = ngx.var.request_uri
        if URL_WHITE_RULES ~= nil then
            for _,rule in pairs(URL_WHITE_RULES) do
                if rule ~= "" and rulematch(REQ_URI,rule,"jo") then
                    return true 
                end
            end
        end
    end
end

function get_cc_v(SERVER_NAME,CC_TOKEN)
    local CC_RULES = get_rule('cc.rule')   
    local CCcount=tonumber(string.match(config_cc_rate,'(.*)/'))
    local CCseconds=tonumber(string.match(config_cc_rate,'/(.*)'))
    if CC_RULES ~= nil then
        for _,rule in pairs(CC_RULES) do
            server_name=string.match(rule,'(.*)|.*')
            if rule ~= "" and  rulematch(SERVER_NAME,server_name,"jo") then
                CCcount=string.match(rule,'.*|(.*)/')
                CCseconds=string.match(rule,'.*|.*/(.*)')
                break
            end
        end
    end
    return CCcount..'/'..CCseconds
end

--deny slow cc attack
function cc_attack_check()
    if config_cc_check == "on" then
        local ATTACK_URI=ngx.var.uri
        local SERVER_NAME = ngx.var.http_host
        local CLIENT_IP = get_client_ip()
        local CC_TOKEN = CLIENT_IP..SERVER_NAME..ATTACK_URI
        local limit = ngx.shared.limit
        local blackip = ngx.shared.blackip
        -- CCcount=tonumber(string.match(config_cc_rate,'(.*)/'))
        -- CCseconds=tonumber(string.match(config_cc_rate,'/(.*)'))
        local req,_ = limit:get(CC_TOKEN)
        CC_V = get_cc_v(SERVER_NAME,CC_TOKEN)
        CCcount=tonumber(string.match(CC_V,'(.*)/'))
        CCseconds=tonumber(string.match(CC_V,'/(.*)'))
        blackip_seconds=tonumber(config_black_ip_cache)
        if req then
            if req > CCcount then
                log_record('CC_Attack',ngx.var.request_uri,"-","-")
        		if config_waf_enable == "on" then
                    blackip:add(CLIENT_IP,1,blackip_seconds)
                    ngx.exit(403)
        		end
            else
                limit:incr(CC_TOKEN,1)
            end
        else
            limit:set(CC_TOKEN,1,CCseconds)
        end
    end
    return false
end

--deny flood(1 second) cc attack

--deny cookie
function cookie_attack_check()
    if config_cookie_check == "on" then
        local COOKIE_RULES = get_rule('cookie.rule')
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil then
            for _,rule in pairs(COOKIE_RULES) do
                if rule ~="" and rulematch(USER_COOKIE,rule,"jo") then
                    log_record('Deny_Cookie',ngx.var.request_uri,"-",rule)
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
             end
	 end
    end
    return false
end

--deny url
function url_attack_check()
    if config_url_check == "on" then
        local URL_RULES = get_rule('url.rule')
        local REQ_URI = ngx.var.request_uri
        for _,rule in pairs(URL_RULES) do
            if rule ~="" and rulematch(REQ_URI,rule,"jo") then
                log_record('Deny_URL',REQ_URI,"-",rule)
                if config_waf_enable == "on" then
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

--deny url args
function url_args_attack_check()
    if config_url_args_check == "on" then
        local ARGS_RULES = get_rule('args.rule')
        for _,rule in pairs(ARGS_RULES) do
            local REQ_ARGS = ngx.req.get_uri_args()
            for key, val in pairs(REQ_ARGS) do
                if type(val) == 'table' then
                    ARGS_DATA = table.concat(val, " ")
                else
                    ARGS_DATA = val
                end
                if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~="" and rulematch(unescape(ARGS_DATA),rule,"joi") then
                    log_record('Deny_URL_Args',ngx.var.request_uri,"-",rule)
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end
--deny user agent
function user_agent_attack_check()
    if config_user_agent_check == "on" then
        local USER_AGENT_RULES = get_rule('useragent.rule')
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil then
            for _,rule in pairs(USER_AGENT_RULES) do
                if rule ~="" and rulematch(USER_AGENT,rule,"jo") then
                    log_record('Deny_USER_AGENT',ngx.var.request_uri,"-",rule)
                    if config_waf_enable == "on" then
		        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

--deny post
function post_attack_check()
    if config_post_check == "on" then
        local POST_RULES = get_rule('post.rule')
        for _,rule in pairs(ARGS_RULES) do
            local POST_ARGS = ngx.req.get_post_args()
        end
        return true
    end
    return false
end 
