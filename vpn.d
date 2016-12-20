#!/usr/bin/rdmd

import core.thread, std.exception, std.json, std.conv, std.array, std.stdio, std.file,
    std.format, std.string, std.socket, std.traits, std.path, std.process;

extern (C) {
    void exit(int);
}

struct IP {
    string ip = "0.0.0.0";
    string port = "0";
    uint u32;
    ushort uport;
    this(string s) {
        auto pos = std.string.indexOf(s, ':');
        if (pos is 0) {
            uport = std.conv.to!ushort(_T.ltrim(s, ':'));
            u32 = std.socket.InternetAddress.parse(this.ip);
            port = std.conv.to!string(uport);
        } else if (pos > 0) {
            scope _port = s[pos + 1 .. $];
            uport = std.conv.to!ushort(_T.ltrim(_port, ':'));
            u32 = std.socket.InternetAddress.parse(s[0 .. pos]);
            port = std.conv.to!string(uport);
        } else {
			pos = std.string.indexOf(s, '.');
			if( pos < 0 ) {
	            uport = std.conv.to!ushort(s);
	            port = std.conv.to!string(uport);
			} else {
	            u32 = std.socket.InternetAddress.parse(s);
			}
        }
        ip = std.socket.InternetAddress.addrToString(u32);

    }
}

struct Section {
    string path;
    char[] section;

    int opApply(int delegate(ref char[], ref char[]) dg) {
        int result = 0;
        scope file = File(this.path);
        scope (exit)
            file.close;
        foreach (ref line; file.byLine) {
            line = _T.trim(line);
            if (line.length is 0)
                continue;
            auto pos = std.string.indexOf(line, ';');
            if (pos is 0)
                continue;
            if (pos > 0) {
                line = line[0 .. pos];
            }
            if (pos is 0)
                continue;
            if (line[0] is '[' && line[$ - 1] is ']') {
                section = _T.trim(line[1 .. $ - 1]).dup;
                continue;
            }
            pos = std.string.indexOf(line, '=');
            char[] key, value;
            if (pos > 0) {
                key = _T.trim(line[0 .. pos]);
                value = _T.trim(line[pos + 1 .. $]);
                if (value.length > 0) {
                    if (value[0] is '"' && value[$ - 1] is '"') {
                        value = value[1 .. $ - 1];
                    }
                }
                dg(key, value);
            } else {
                dg(key, line);
            }
        }
        return result;
    }
}

struct _T {
    
    static string[] split(string input, string p = " \t\n\r" ){
        string[] output ;
        if( p is null || p.length is 0 ){
          return output ;
        }
        auto plen = p.length ;
        auto len = input.length ;
        ptrdiff_t last_element_index = -1 ;
        for( size_t i = 0; i < len ; i++ ) {
          bool matched = false ;
          for(size_t j=0; j < plen; j++ ) {
            if(p[j] is input[i]) {
              matched = true ;
              break ;
            }
          }
          
          if( matched ) {
            if( last_element_index !is -1 ) {
              output  ~= input[last_element_index .. i] ;
              last_element_index  = -1 ;
            }
            continue ;
          }
          // start_index
          if(  last_element_index is -1 ) {
            last_element_index  = i ;
          }
        }
        if( last_element_index !is -1) {
              output  ~= input[last_element_index .. $] ;
        }
        return output ;
    }
    
    static ref string ltrim(ref string s, char c = ' ') {
        while (s.length > 0) {
            if (s[0] is c) {
                s = s[1 .. $];
                continue;
            }
            break;
        }
        return s;
    }

    static T trim(T)(T ret) {
        while (ret.length > 0) {
            if (ret[0] !is '\r' && ret[0] !is '\n' && ret[0] !is ' ' && ret[0] !is '\t') {
                break;
            }
            ret = ret[1 .. $];
        }
        while (ret.length > 0) {
            if (ret[$ - 1] !is '\r' && ret[$ - 1] !is '\n' && ret[$ - 1] !is ' ' && ret[$ - 1] !is '\t') {
                break;
            }
            ret = ret[0 .. $ - 1];
        }
        return ret;
    }

    static string find2(ref string str, string from, string to) {
        auto pos = std.string.indexOf(str, from);
        if (pos < 0) {
            return null;
        }
        string data = str[pos + from.length .. $];
        pos = std.string.indexOf(data, to);
        if (pos >= 0) {
            str = data[pos + 1 .. $];
            return data[0 .. pos];
        }
        return null;
    }

    static const(JSONValue)* getJsonValue(T)(ref T t, const(JSONValue)* pObj, string key, ref bool exists) {
        scope const(JSONValue)* p = key in *pObj;
        if (p !is null) {
            exists = true;
            static if (isBoolean!T) {
                exists = true;
                if (p.type is JSON_TYPE.TRUE) {
                    t = true;
                } else if (p.type is JSON_TYPE.FALSE || p.type is JSON_TYPE.NULL) {
                    t = false;
                } else if (p.type is JSON_TYPE.INTEGER) {
                    t = p.integer ? true : false;
                } else if (p.type is JSON_TYPE.UINTEGER) {
                    t = p.uinteger ? true : false;
                } else if (p.type is JSON_TYPE.FLOAT) {
                    t = p.floating ? true : false;
                } else {
                    return p;
                }
            }
            // isUnsigned!T 
            static if (isIntegral!T) {
                if (p.type is JSON_TYPE.INTEGER) {
                    t = cast(T)p.integer;
                } else if (p.type is JSON_TYPE.UINTEGER) {
                    t = cast(T)p.uinteger;
                } else if (p.type is JSON_TYPE.FLOAT) {
                    t = std.conv.to!T(p.floating);
                } else if (p.type is JSON_TYPE.TRUE) {
                    t = 1;
                } else if (p.type is JSON_TYPE.FALSE || p.type is JSON_TYPE.NULL) {
                    t = 0;
                } else if (p.type is JSON_TYPE.STRING) {
                    t = std.conv.to!T(p.str);
                } else {
                    return p;
                }
            }
            static if (isFloatingPoint!T) {
                if (p is JSON_TYPE.FLOAT) {
                    t = std.conv.to!T(p.floating);
                } else if (p.type is JSON_TYPE.INTEGER) {
                    t = cast(T)p.integer;
                } else if (p.type is JSON_TYPE.UINTEGER) {
                    t = cast(T)p.uinteger;
                } else if (p.type is JSON_TYPE.TRUE) {
                    t = 1;
                } else if (p.type is JSON_TYPE.FALSE || p.type is JSON_TYPE.NULL) {
                    t = 0;
                } else if (p.type is JSON_TYPE.STRING) {
                    t = std.conv.to!T(p.str);
                } else {
                    return p;
                }
            }
            static if (isSomeString!T) {
                if (p.type is JSON_TYPE.STRING) {
                    t = std.conv.to!T(p.str).dup;
                } else if (p.type is JSON_TYPE.FLOAT) {
                    t = std.conv.to!T(p.floating);
                } else if (p.type is JSON_TYPE.INTEGER) {
                    t = std.conv.to!T(p.integer);
                } else if (p.type is JSON_TYPE.UINTEGER) {
                    t = std.conv.to!T(p.uinteger);
                } else if (p.type is JSON_TYPE.TRUE) {
                    t = std.conv.to!T(true);
                } else if (p.type is JSON_TYPE.FALSE) {
                    t = std.conv.to!T(false);
                } else if (p.type is JSON_TYPE.NULL) {
                    t = std.conv.to!T(null);
                } else {
                    return p;
                }
            }
        } else {
            exists = false;
        }
        return null;
    }
}

struct iProcess {
    string cmd;
    string pid_file;
    string log_file;
	string stop_cmd;

    this(string c, string p, string l, string k = null) {
        cmd = c;
        pid_file = p;
        log_file = l;
		stop_cmd = k;
    }
}

struct iRedir {
    string ip;
    IP[ushort] redirs;
    
    static iRedir*[string] list;
    static void load(string line) {
      auto ls = _T.split(line) ;
      if( ls.length is 0){
        return ;
      }
      string ip = ls[0] ;
      auto it = new iRedir(ip) ;
      list[ ip ] = it ;
      if( ls.length is 1){
        return ;
      }
      foreach( _line ;ls[1..$]) {
        auto _ls = _T.split(_line, ":") ;
        auto _ip = IP(_ls[0]) ;
        if( _ip.u32 !is 0 ) {
          _G.Error("invalid rules:%s, can not use 0.0.0.0 as redir target", line);
        }
        if( _ip.uport is 0 ) {
          _G.Error("invalid rules:%s, can not use 0.0.0.0:0 as redir target", line);
        }
        switch(_ls.length) {
          case 1:
            it.redirs[ _ip.uport ] = IP( ip ~ ':' ~ _ip.port );
            break;
          case 2:
            auto pos = std.string.indexOf(_ls[1], '.');
            if( pos >= 0 && pos < _ls[1].length ) {
              _G.Error("invalid rules:%s can not use ip(%s) without port.", line, _ls[1]) ;
            }
            auto _ip2 = IP(_ls[1]) ;
            if( _ip2.uport is 0) {
              _G.Error("invalid rules:%s can not use target port(%s) as 0", line, _ls[1] );
            }
            it.redirs[ _ip.uport ] = IP( ip ~ ':' ~ _ip2.port );
            break;
          case 3:
            auto _ip2 = IP(_ls[1] ~ ":" ~ _ls[2] ) ;
            if( _ip2.uport is 0) {
              _G.Error("invalid rules:%s can not use target (%s:%s) port as 0", line, _ls[1], _ls[2] );
            }
            if( _ip2.u32 is 0) {
              _G.Error("invalid rules:%s can not use target (%s:%s) ip as 0.0.0.0", line, _ls[1], _ls[2] );
            } 
            it.redirs[ _ip.uport ] = _ip2 ;
            break;
          default:
            _G.Error("invalid rules:%s", line);
            ;
        }
      }
    }
}

struct Proxy {
    enum Type {
        Server = 0,
        Client,
        Redir,
        Dns
    }

    Type type;
    string name;

    string server;
    ushort server_port = 0;
    string local_address = "0.0.0.0";
    ushort local_port = 0;

    string password;
    string method = "aes-128-cfb";
    bool auth = false;

    ushort timeout = 45;
    bool verbose = true;
    bool fast_open = false;
    bool udp_relay = true;

    string nameserver;

    bool enabled = true;
    bool udp_only = false;
    bool is_lazy_proxy = false;
    bool sudo  = false ;
	
	bool ssr	= false ;
	bool dns_ipv6	= false ;
	bool connect_verbose_info = false ;
	string protocol = "auth_sha1_v4" ;
	string protocol_param = "" ;
	string obfs = "http_simple" ;
	string obfs_param = "" ;
	string redirect = "" ;
	
	string bin = "" ;
	
    void loadFromiFree(string name, string ip, string port, string method, string psword,
        ushort local_port, Proxy* local) {
        this.type = Type.Client;
        this.name = name;
        this.server = ip;
        this.server_port = std.conv.to!ushort(port);
        this.local_port = local_port;
        this.password = psword;
        this.method = method;
        this.timeout = local.timeout;
        this.verbose = local.verbose;
        this.fast_open = local.fast_open;
        this.udp_relay = local.udp_relay;
        this.is_lazy_proxy	= true ;
    }

    const(JSONValue)* loadFromJsonValue(Type _type, string _name, const(JSONValue)* pParent,
        Proxy* _default) {
        type = _type;
        name = _name;
        const(JSONValue)* pJson = _name in *pParent;
        if (pJson is null) {
            return null;
        }
        if (pJson.type !is JSON_TYPE.OBJECT) {
            return null;
        }
        bool exists;
        _T.getJsonValue!ushort(server_port, pJson, "server_port", exists);
        if (exists) {
            _T.getJsonValue!string(server, pJson, "server", exists);
            if (!exists) {
                if (type is Type.Server) {
                    server = "0.0.0.0";
                } else if (_default) {
                    server = _default.server;
                } else {
                    _G.Error("json(%s).server not exists!", _name);
                    _G.Exit(__LINE__);
                }
            }
        } else {
            _T.getJsonValue!string(server, pJson, "server", exists);
            if (exists) {
                scope server_ip = IP(server);
                server = server_ip.ip;
                if (server_ip.uport !is 0) {
                    server_port = server_ip.uport;
                } else if (_default) {
                    server_port = _default.server_port;
                } else {
                    _G.Error("json(%s).server_port is 0!", _name);
                    _G.Exit(__LINE__);
                }
            } else if (_default) {
                if (type is Type.Server) {
                    server = "0.0.0.0";
                    server_port = 8388;
                } else {
                    server = _default.server;
                    server_port = _default.server_port;
                }
            } else {
                _G.Error("json(%s).server not exists!", _name);
                _G.Exit(__LINE__);
            }
        }
        if (type !is Type.Server) {
            if ("0.0.0.0" == server) {
                _G.Error("json(%s).server can not be %s!", _name, server);
                _G.Exit(__LINE__);
            }
        }
        if (0 is server_port) {
            _G.Error("json(%s).server_port can not be %s!", _name, server_port);
            _G.Exit(__LINE__);
        }

        _T.getJsonValue!ushort(local_port, pJson, "local_port", exists);
        if (exists) {
            _T.getJsonValue!string(local_address, pJson, "local_address", exists);
            if (!exists) {
                if (type is Type.Server || type is Type.Redir) {
                    local_address = "0.0.0.0";
                } else if (type is Type.Dns) {
                    local_address = "127.0.0.1";
                } else if (type is Type.Client) {
                    local_address = _G.lan_ip;
                } else if (_default) {
                    local_address = _default.local_address;
                } else {
                    _G.Error("json(%s).local_address not exists!", _name);
                    _G.Exit(__LINE__);
                }
            }
        } else {
            _T.getJsonValue!string(local_address, pJson, "local_address", exists);
            if (exists) {
                scope local_ip = IP(local_address);
                local_address = local_ip.ip;
                if (local_ip.uport !is 0) {
                    local_port = local_ip.uport;
                }
            } else {
                _T.getJsonValue!string(local_address, pJson, "local", exists);
                if (exists) {
                    scope local_ip = IP(local_address);
                    local_address = local_ip.ip;
                    if (local_ip.uport !is 0) {
                        local_port = local_ip.uport;
                    }
                } else if (_default) {
                    if (type is Type.Server || type is Type.Redir) {
                        local_address = "0.0.0.0";
                    } else if (type is Type.Dns) {
                        local_address = "127.0.0.1";
                    } else if (type is Type.Client) {
                        local_address = _G.lan_ip;
                    } else {
                        local_address = _default.local_address;
                    }
                }
            }
        }

        if (type !is Type.Server) {
            if (0 is local_port) {
                if (type is Type.Dns) {
                    local_port = 5300;
                } else if (type is Type.Client) {
                    local_port = 7777;
                } else if (type is Type.Redir) {
                    local_port = _default ? 1055 : 1053;
                } else {
                    _G.Error("json(%s).local_port can not be %s!", _name, local_port);
                    _G.Exit(__LINE__);
                }
            }
        }
		
        _T.getJsonValue!string(password, pJson, "password", exists);
        if (!exists) {
            _T.getJsonValue!string(password, pJson, "pass", exists);
        }
        if (!exists) {
            _T.getJsonValue!string(password, pJson, "psword", exists);
        }
        if (!exists) {
            if (_default) {
                password = _default.password;
            } else {
                _G.Error("json(%s).password can not be null!", _name);
                _G.Exit(__LINE__);
            }
        }

        _T.getJsonValue!bool(auth, pJson, "auth", exists);
        if (!exists) {
            if (_default) {
                auth = _default.auth;
            }
        }
        _T.getJsonValue!string(method, pJson, "method", exists);
        if (!exists && _default) {
            method = _default.method;
        }
        _T.getJsonValue!ushort(timeout, pJson, "timeout", exists);
        if (!exists && _default) {
            timeout = _default.timeout;
        }
        _T.getJsonValue!bool(verbose, pJson, "verbose", exists);
        if (!exists && _default) {
            verbose = _default.verbose;
        }
        _T.getJsonValue!bool(udp_relay, pJson, "udp_relay", exists);
        if (!exists && _default) {
            udp_relay = _default.udp_relay;
        }

        _T.getJsonValue!bool(fast_open, pJson, "fast_open", exists);
        if (!exists && _default) {
            fast_open = _default.fast_open;
        }

        if (type is Type.Server) {
            _T.getJsonValue!string(nameserver, pJson, "nameserver", exists);
            if (!exists) {
                nameserver = "127.0.0.1";
            } else {
                auto ip = IP(nameserver);
                if (ip.uport is 0 || ip.uport is 53) {
                    nameserver = ip.ip ;
                } else {
                    nameserver = ip.ip ~ ":" ~ ip.port;
                }
            }
        }
        if (type is Type.Dns) {
            _T.getJsonValue!string(nameserver, pJson, "nameserver", exists);
            if (!exists) {
                nameserver = "8.8.8.8";
            } else {
                auto ip = IP(nameserver);
                if (ip.uport is 0 || ip.uport is 53) {
                    nameserver = ip.ip ;
                } else {
                    nameserver = ip.ip ~ ":" ~ ip.port;
                }
            }
        }
		
        _T.getJsonValue!string(bin, pJson, "bin", exists);
		
        _T.getJsonValue!bool(ssr, pJson, "ssr", exists);
		if( !exists && _default ) {
			ssr	= _default.ssr ;
		}
		if (!ssr) {
			return pJson ;
		}
		
        _T.getJsonValue!bool(dns_ipv6, pJson, "dns_ipv6", exists);
		if( !exists && _default ) {
			dns_ipv6	= _default.dns_ipv6 ;
		}
        _T.getJsonValue!bool(connect_verbose_info, pJson, "connect_verbose_info", exists);
		if( !exists && _default ) {
			connect_verbose_info	= _default.connect_verbose_info ;
		}
        _T.getJsonValue!string(protocol, pJson, "protocol", exists);
		if( !exists && _default ) {
			protocol	= _default.protocol ;
		}
        _T.getJsonValue!string(protocol_param, pJson, "protocol_param", exists);
		if( !exists && _default ) {
			protocol_param	= _default.protocol_param ;
		}
        _T.getJsonValue!string(obfs, pJson, "obfs", exists);
		if( !exists && _default ) {
			obfs	= _default.obfs ;
		}
        _T.getJsonValue!string(obfs_param, pJson, "obfs_param", exists);
		if( !exists && _default ) {
			obfs_param	= _default.obfs_param ;
		}
        _T.getJsonValue!string(redirect, pJson, "redirect", exists);
		if( !exists && _default ) {
			redirect	= _default.redirect ;
		}
        return pJson;
    }

    void check(ref string[ushort] exists) {
        if (!enabled) {
            return;
        }
        string* p;
        if (type is Type.Server) {
            p = server_port in exists;
        } else {
            p = local_port in exists;
        }
        if (p !is null) {
            _G.Error("%s(port) conflict with %s(port)", *p, name);
            _G.Exit(__LINE__);
        }
        if (type is Type.Server) {
            exists[server_port] = name;
        } else {
            exists[local_port] = name;
        }
    }

    void dump() {
        writefln("%s=%s server=%s:%d local=%s:%d  auth=%s,%s,%s", name, enabled, server,
            server_port, local_address, local_port, method, password, auth);
    }

    void initProcess(ref iProcess*[] pool) {
        if (!enabled) {
            return;
        }
        string log = "/tmp/log/svpn-" ~ name ~ ".log";
        string pid = "/tmp/run/svpn-" ~ name ~ ".pid";
        string path = "/tmp/etc/svpn-" ~ name ~ ".json";
        string _cmd = "";
        _cmd ~= " -c " ~ path;
        JSONValue j = ["server" : server, "method" : method, "password" : password];
        j["server_port"] = server_port;
        if (type !is Type.Server) {
            j["local_address"] = local_address;
            j["local_port"] = local_port;
        } else {
            j["nameserver"] = nameserver;
        }
        j["timeout"] = timeout;
        j["verbose"] = verbose;
        j["udp_relay"] = udp_relay;
        j["auth"] = auth;

		if (type !is Type.Redir) {
	        if (fast_open) {
	            j["fast_open"] = true ;
	        }
		}
		
		if( ssr ) {
			j["protocol"] = protocol ;
			j["protocol_param"] = protocol_param ;
			j["obfs"] = obfs ;
			j["obfs_param"] = obfs_param ;
			j["redirect"] = redirect ;
			j["dns_ipv6"] = dns_ipv6 ;
			j["connect_verbose_info"] = connect_verbose_info ;
		}

		if (type is Type.Dns) {
            _cmd ~= " -L " ~ nameserver ;
		}
        if (udp_relay) {
            if (udp_only) {
                _cmd ~= " -U";
            } else {
                _cmd ~= " -u";
            }
        }
		if( !bin || bin.length is 0 ) {
			string bin_prefix = "ss" ;
			if( ssr ) {
				bin_prefix	= "ssr" ;
			}
	        if (type is Type.Redir) {
				if ("udp" == name) {
					bin = bin_prefix ~ "-redir-udp";
				} else {
		            bin = bin_prefix ~ "-redir";
				}
	        } else if (type is Type.Dns) {
	            bin = bin_prefix ~ "-tunnel";
	        } else if (type is Type.Server) {
	            bin = bin_prefix ~ "-server";
	        } else if (type is Type.Client) {
	            bin = bin_prefix ~ "-local";
	        }
		}
        std.file.write(path, j.toString());
        _cmd ~= " -f " ~ pid ~ " >" ~ log ~ " 2>&1 &";
        _cmd = bin ~ _cmd ;
        if ( sudo ) {
	        _cmd = "sudo -u " ~ _G.sudo_user ~ " -H " ~ _cmd ;
        }
        pool ~= new iProcess(_cmd, pid, log);
    }
}

struct _Environment {
    string exe_path;
    string etc_dir;
    string lan_ip;
    string lan_netmask;
    string wan_name;
	  string sudo_user = "ftp" ;

    bool adbyby_enable;
    bool force_reload = false;
    bool verbose = false;
    IP adbyby_ip;

    bool use_tproxy = true;
    bool use_output = true;

    bool proxy_flushed = false;

    string[ushort] bind_port_list;

    Proxy default_proxy;
    Proxy dns_proxy;
    Proxy udp_proxy;
    Proxy server_proxy;
    Proxy local_proxy;

    Proxy[] free_proxies;

    string[] bypass_rules;
    string[] proxy_rules;

    iProcess*[] base_proc;
    iProcess*[] lazy_proc;

    void Exit(int i) {
        _G.Error("exit(%d)", i);
        exit(i);
    }

    void Init() {
        _env_init;
        _config_init;
        _rules_init;
    }

    void _env_init() {
        exe_path = thisExePath;
        etc_dir = dirName(exe_path);
        lan_ip = Exec("uci get network.lan.ipaddr");
        lan_netmask = Exec("uci get network.lan.netmask");
        auto proto = Exec("uci get network.wan.proto");
        if ("pppoe" == proto) {
            wan_name = "pppoe-wan";
        } else {
            wan_name = Exec("uci get network.wan.ifname");
        }
    }

    void _adbyby_init() {
        scope path = etc_dir ~ "/adhook.ini";
        if (!path.exists) {
            Error("%s not exists!", path);
            Exit(__LINE__);
        }
        scope sec = Section(path);
        foreach (ref key, ref value; sec) {
            if ("cfg" == sec.section && key == "listen-address") {
                adbyby_ip = IP(cast(string)value);
                break;
            }
        }
    }

    void _config_init() {
        scope path = etc_dir ~ "/vpn.json";

        if (!path.exists) {
            Error("%s not exists!", path);
            Exit(__LINE__);
        }
        scope data = path.readText;
        scope jRoot = parseJSON(data);
        enforce(jRoot.type is JSON_TYPE.OBJECT);
        bool exists;
        _T.getJsonValue!bool(adbyby_enable, &jRoot, "adbyby", exists);
        if (adbyby_enable) {
            _adbyby_init;
        }
        auto p = default_proxy.loadFromJsonValue(Proxy.Type.Redir, "default", &jRoot, null);
        if (p is null) {
            Error("default node not exists in file: %s", path);
            _G.Exit(__LINE__);
        }
        
        p = dns_proxy.loadFromJsonValue(Proxy.Type.Dns, "dns", &jRoot, &default_proxy);
        dns_proxy.udp_relay = true;
        if (p is null) {
            bool has_dns = false;
            string dns_value = null;
            auto pDns = _T.getJsonValue!bool(has_dns, &jRoot, "dns", exists);
            if (!exists) {
                // not setting, use default server as dns 
                has_dns = true;
            } else if (pDns is null || pDns.type !is JSON_TYPE.STRING) {
                if (!has_dns) {
                    dns_proxy.enabled = false;
                }
            } else if (pDns.type is JSON_TYPE.STRING) {
                _T.getJsonValue!string(dns_value, &jRoot, "dns", exists);
                if (exists && dns_value !is null && dns_value.length > 1) {
                    auto dns_ip = IP(dns_value);
                    if (dns_ip.uport is 0 || dns_ip.uport is 53) {
                        dns_value = dns_ip.ip ;
                    } else {
                        dns_value = dns_ip.ip ~ ":" ~ dns_ip.port;
                    }
                } else {
                    dns_value = null;
                }
            }

            if (has_dns || dns_value) {
                dns_proxy.server = default_proxy.server;
                dns_proxy.server_port = default_proxy.server_port;
                dns_proxy.local_address = "127.0.0.1";
                dns_proxy.local_port = 5300;
                dns_proxy.method = default_proxy.method;
                dns_proxy.password = default_proxy.password;
                dns_proxy.auth = default_proxy.auth;
                dns_proxy.timeout = default_proxy.timeout;
                dns_proxy.verbose = default_proxy.verbose;
                dns_proxy.fast_open = default_proxy.fast_open;

                dns_proxy.ssr = default_proxy.ssr;
                dns_proxy.dns_ipv6 = default_proxy.dns_ipv6;
                dns_proxy.connect_verbose_info = default_proxy.connect_verbose_info;
                dns_proxy.protocol = default_proxy.protocol;
                dns_proxy.protocol_param = default_proxy.protocol_param;
                dns_proxy.obfs = default_proxy.obfs;
                dns_proxy.obfs_param = default_proxy.obfs_param;
                dns_proxy.redirect = default_proxy.redirect;

                if (dns_value) {
                    dns_proxy.nameserver = dns_value;
                } else {
                    dns_proxy.nameserver = "8.8.8.8";
                }
            }
        }
        
        p = udp_proxy.loadFromJsonValue(Proxy.Type.Redir, "udp", &jRoot, &dns_proxy);
        udp_proxy.name = "udp";
        udp_proxy.udp_relay = true;
        udp_proxy.udp_only = true;
        if (p is null) {
            udp_proxy.enabled = false;
            bool has_udp = false;
            string udp_value = null;
            auto pUdp = _T.getJsonValue!bool(has_udp, &jRoot, "udp", exists);
            if (!exists) {
                // not setting , use dns local port 
                udp_proxy.local_port = dns_proxy.local_port ;
            } else if (pUdp is null || pUdp.type !is JSON_TYPE.STRING) {
                if (has_udp) {
                    // use dns local port 
                    udp_proxy.local_port = dns_proxy.local_port;
                } else {
                    use_tproxy = false;
                }
            } else if (pUdp.type is JSON_TYPE.STRING) {
                _T.getJsonValue!string(udp_value, &jRoot, "udp", exists);
                if (exists && udp_value !is null && udp_value.length > 1) {
                    auto udp_ip = IP(udp_value);
                    if ("0.0.0.0" == udp_ip.ip) {
                        udp_proxy.server = dns_proxy.server;
                    } else {
                        udp_proxy.server = udp_ip.ip;
                    }
                    if (udp_ip.uport is 0) {
                        udp_proxy.server_port = dns_proxy.server_port;
                    } else {
                        udp_proxy.server_port = udp_ip.uport;
                    }
                } else {
                    udp_value = null;
                }
            }
            if (udp_value) {
                udp_proxy.local_address = "0.0.0.0";
                udp_proxy.local_port = 1055;
                udp_proxy.method = dns_proxy.method;
                udp_proxy.password = dns_proxy.password;
                udp_proxy.auth = dns_proxy.auth;
                udp_proxy.timeout = dns_proxy.timeout;
                udp_proxy.verbose = dns_proxy.verbose;
                udp_proxy.fast_open = dns_proxy.fast_open;
				
                udp_proxy.enabled = true;
            }
        }
        
        p = server_proxy.loadFromJsonValue(Proxy.Type.Server, "server", &jRoot, &default_proxy);
        server_proxy.sudo = true ;
        if (p is null) {
            bool has_server = false;
            _T.getJsonValue!bool(has_server, &jRoot, "server", exists);
            if (exists && !has_server) {
                server_proxy.enabled = false;
            } else {
                server_proxy.server = "0.0.0.0";
                server_proxy.server_port = 8388;
                server_proxy.method = default_proxy.method;
                server_proxy.password = default_proxy.password;
                server_proxy.auth = default_proxy.auth;
                server_proxy.timeout = default_proxy.timeout;
                server_proxy.verbose = default_proxy.verbose;
                server_proxy.fast_open = default_proxy.fast_open;
                server_proxy.udp_relay = true;
                server_proxy.nameserver = _G.lan_ip ;
				
                server_proxy.ssr = default_proxy.ssr;
                server_proxy.dns_ipv6 = default_proxy.dns_ipv6;
                server_proxy.connect_verbose_info = default_proxy.connect_verbose_info;
                server_proxy.protocol = default_proxy.protocol;
                server_proxy.protocol_param = default_proxy.protocol_param;
                server_proxy.obfs = default_proxy.obfs;
                server_proxy.obfs_param = default_proxy.obfs_param;
                server_proxy.redirect = default_proxy.redirect;
				
            }
        }
        p = local_proxy.loadFromJsonValue(Proxy.Type.Client, "local", &jRoot, &default_proxy);
        local_proxy.sudo = true ;
        if (p is null) {
            bool has_local = false;
            _T.getJsonValue!bool(has_local, &jRoot, "local", exists);
            if (exists && !has_local) {
                local_proxy.enabled = false;
            } else {
                local_proxy.server = default_proxy.server;
                local_proxy.server_port = default_proxy.server_port;
                local_proxy.local_address = lan_ip;
                local_proxy.local_port = 7777;
                local_proxy.method = default_proxy.method;
                local_proxy.password = default_proxy.password;
                local_proxy.auth = default_proxy.auth;
                local_proxy.timeout = default_proxy.timeout;
                local_proxy.verbose = default_proxy.verbose;
                local_proxy.fast_open = default_proxy.fast_open;
                local_proxy.udp_relay = default_proxy.udp_relay;
				
                local_proxy.ssr = default_proxy.ssr;
                local_proxy.dns_ipv6 = default_proxy.dns_ipv6;
                local_proxy.connect_verbose_info = default_proxy.connect_verbose_info;
                local_proxy.protocol = default_proxy.protocol;
                local_proxy.protocol_param = default_proxy.protocol_param;
                local_proxy.obfs = default_proxy.obfs;
                local_proxy.obfs_param = default_proxy.obfs_param;
                local_proxy.redirect = default_proxy.redirect;
				
            }
        }

        if (adbyby_enable) {
            bind_port_list[adbyby_ip.uport] = "adbyby";
        }
        default_proxy.check(bind_port_list);
        udp_proxy.check(bind_port_list);
        dns_proxy.check(bind_port_list);
        server_proxy.check(bind_port_list);
        local_proxy.check(bind_port_list);
    }

    void _rules_init() {
        scope path = etc_dir ~ "/ignore.list";
        if (!path.exists) {
            Error("%s not exists!", path);
            Exit(__LINE__);
        }
        scope file = File(path);
        scope (exit)
            file.close;

        static string strip32(char[] line) {
            if (line.length < 1) {
                return null;
            }
            line = line[1 .. $];
            auto pos = std.string.indexOf(line, '/');
            if (pos > 0 && _T.trim(line[pos + 1 .. $]) == "32") {
                line = _T.trim(line[0 .. pos]);
            }
            return line.idup;
        }

        foreach (ref line; file.byLine) {
            line = _T.trim(line);
            if (line.length is 0 || line[0] is ';')
                continue;
            auto pos = std.string.indexOf(line, ';');
            if (pos > 0) {
                line = _T.trim(line[0 .. pos]);
            }
            if (line.length is 0)
                continue;
            switch (line[0]) {
            case '#':
                bypass_rules ~= strip32(line);
                break;
            case '!':
                iRedir.load(strip32(line));
                break;
            default:
                proxy_rules ~= line.idup;
            }
        }
    }

    string Exec(string _cmd, bool exit = true, bool print_cmd = false) {
        if (print_cmd) {
            Error("\n>>> execute: %s \n", _cmd);
        }
        auto ls = executeShell(_cmd);
        if (ls.status != 0) {
            if (print_cmd) {
                Error("\n>>> return: %d\n", ls.status);
            } else {
                Error("\n>>> execute: %s \n>>> return: %d\n", _cmd, ls.status);
            }
            if (exit) {
                Exit(ls.status);
            }
        }
        return _T.trim(ls.output);
    }

    void Error(T...)(string fmt, T t) {
        auto writer = appender!string();
        formattedWrite(writer, fmt, t);
        writeln(writer.data);
    }

    void dump() {
        writefln("lan=%s/%s", lan_ip, lan_netmask);
        default_proxy.dump;
        dns_proxy.dump;
        server_proxy.dump;
        local_proxy.dump;
        writefln("adbyby=%s", adbyby_enable);
        writefln("ports=%s", bind_port_list);
    }

    void tryGetFreeServer() {
        string path = "/tmp/ifree_proxy_cache.html";
        string url = `http://www.ishadowsocks.net/`;
        if (path.exists) {
            std.file.remove(path);
        }
        _G.Exec("curl -L -o " ~ path ~ " " ~ url, true);
        if (!path.exists) {
            writefln("curl(%s) %s not exists!", url, path);
            return;
        }
        string data = std.file.readText(path);
        parseFreeProxy(data, url);
    }

    void parseFreeProxy(string data, string url) {
        string sections = _T.find2(data, `<!-- Free Shadowsocks Section -->`, `</section>`);
        if (sections is null || sections.length < 10) {
            writefln("curl(%s) no sections: %s", url, data);
            _G.Exit(__LINE__);
        }

        free_proxies.length = 0;

        ushort local_port = 7000;
        int index = 1;
        do {
            string section = _T.find2(sections, `<div class="col-lg-4 text-center">`, ` </div>`);
            if (section is null) {
                break;
            }
            section = _T.trim(section);
            if (section.length is 0)
                continue;

            string host = _T.find2(section, `服务器地址:`, `</h4>`);
            string ip;
            string port = _T.find2(section, `端口:`, `</h4>`);
            string psword = _T.find2(section, `密码:`, `</h4>`);
            string method = _T.find2(section, `加密方式:`, `</h4>`);
            string status_line = _T.find2(section, `状态`, `</h4>`);
            bool status = std.string.indexOf(status_line, `正常`) >= 0 ? true : false;
            try {
                auto addresses = getAddress(host);
                foreach (address; addresses) {
                    ip = address.toAddrString();
                    break;
                }
            }
            catch (SocketException e) {
                writefln("getAddress(host):%s", host, e);
                continue;
            }
            string name = "ifree" ~ std.conv.to!string(index);
            while (local_port in bind_port_list) {
                local_port++;
            }
            bind_port_list[local_port] = name;

            auto pProxy = new Proxy;
            pProxy.loadFromiFree(name, ip, port, method, psword, local_port, &local_proxy);
            free_proxies ~= *pProxy;
            index++;
        }
        while (sections.length > 10);
    }

    void InitPorc(bool _lazy = false) {
        if (_lazy) {
            tryGetFreeServer();
            foreach (ref proxy; free_proxies) {
                proxy.initProcess(lazy_proc);
                if (_G.verbose) {
                    proxy.dump;
                }
            }
        } else {
            default_proxy.initProcess(base_proc);
            udp_proxy.initProcess(base_proc);
            dns_proxy.initProcess(base_proc);
            server_proxy.initProcess(base_proc);
            local_proxy.initProcess(base_proc);
            if (adbyby_enable) {
                string log = "/tmp/log/adbyby.log";
                string pid = "/tmp/run/adbyby.pid";
                string cmd = "sudo -u nobody -g nogroup  -H " ~ etc_dir ~ "/adbyby --no-daemon > " ~ log ~ " 2>&1 & ";
                base_proc ~= new iProcess(cmd, pid, log, "killall adbyby");
            }
        }
    }

    void stop(bool _lazy = false) {
        foreach (ref proc; _lazy ? lazy_proc : base_proc) {
        	if( _G.verbose ) {
          	  writefln(">>> stop: pid=%s,%s , _G.force_reload=%s", proc.pid_file, proc.pid_file.exists, _G.force_reload);
        	}
        	if (proc.pid_file.exists) {
                if( !_G.force_reload ) {
	                string cmd = "kill `cat " ~ proc.pid_file ~ "`";
	                Exec(cmd, false);
	                Thread.sleep(dur!("msecs")(10));
				}
                if (proc.pid_file.exists)
                    std.file.remove(proc.pid_file);
            } else {
				if( proc.stop_cmd !is null) {
					Exec(proc.stop_cmd, false);
				}
			}
		}
        firewall(true, _lazy);
    }

    void start(bool _lazy = false) {
        foreach (ref proc; _lazy ? lazy_proc : base_proc) {
            if (proc.pid_file.exists && !force_reload) {
                writefln(">>> execute: %s ", proc.cmd);
                writefln(">>> skip: %s already exists!", proc.pid_file);
            } else {
                Exec(proc.cmd, false, true);
            }
        }
		firewall(false, _lazy);
    }

    void firewall(bool _flush, bool _lazy) {
        auto writer = appender!string();
        static string ipath = "/tmp/svpn_ifree.sh" ;
		if( _lazy ) {
			if( _flush ) {
	            if (ipath.exists) {
                	writefln(">>>: flush lazy firewall");
		            Exec("/bin/sh " ~ ipath, false);
	                std.file.remove(ipath);
				} else {
                	writefln(">>>: skip flush lazy firewall");
				}
			} else {
	            writefln(">>>: load lazy firewall");
				foreach(ref proc;lazy_proc) {
			        formattedWrite(writer, "[ -f %s ] && kill `cat %s`\n", proc.pid_file, proc.pid_file);
			        formattedWrite(writer, "rm -rf %s\n", proc.pid_file);
				}
		        foreach (ref proxy; free_proxies) {
					if( proxy.is_lazy_proxy ){
			        	formattedWrite(writer, "#ip=%s\n", proxy.server);
						Exec( `/bin/sh -c "ipset add gfwset ` ~ proxy.server ~ ` nomatch" || echo 1` , false);
					}
		        }
	            std.file.write(ipath, writer.data);
			}
			return ;
		}
		
        bool use_udp_forward = false;
        bool use_udp_output = false;
        if (use_udp_forward || use_udp_output) {
            if (use_udp_forward && use_udp_output) {
                _G.Error("error");
            }
        }
		
        static string path = "/tmp/svpn_shell.sh";
        static string forward_chain = "SVPN_FORWARD";
        static string nat_chain = "SVPN_NAT";
        static string udp_chain = "SVPN_UDP";
        static string tproxy_chain = "SVPN_TPROXY";
        void remove_rules(string table) {
            auto rules = Exec("iptables-save -t " ~ table, true);
            static string match = " SVPN_";
            static string gfw_dst = " gfwset dst ";
            foreach (ref string rule; lineSplitter(rules)) {
                auto pos = indexOf(rule, match);
                auto pos2 = indexOf(rule, gfw_dst);
                if (pos < 1 && pos2 < 1) {
                    continue;
                }
                auto cmd = "iptables -t " ~ table ~ " -D" ~ _T.trim(rule)[2 .. $];
                Exec(cmd, true);
            }
        }

        void do_flush() {
            if (proxy_flushed) {
                return;
            }
			if( use_udp_forward || use_udp_output ) {
	            Exec("iptables -t filter -F " ~ forward_chain, false);
            	Exec("iptables -t nat -F " ~ udp_chain, false);
			}
            Exec("iptables -t nat -F " ~ nat_chain, false);
			if( use_tproxy ) {
            	Exec("iptables -t mangle -F " ~ tproxy_chain, false);
			}
            Exec("iptables -t filter -F forwarding_rule", false);
            Exec("iptables -t nat -F prerouting_rule", false);
            Exec("iptables -t nat -F zone_lan_prerouting", false);

            remove_rules("filter");
            remove_rules("nat");
            remove_rules("mangle");
            if (use_tproxy) {
                Exec("ip rule del fwmark 0x01/0x01 table 100", false);
                Exec("ip route del local 0.0.0.0/0 dev lo table 100", false);
            }
            Exec("ipset -X gfwset", false);
            proxy_flushed = true;
        }

        if (_flush) {
            writefln(">>>: flush iptables");
            do_flush();
            if (path.exists)
                std.file.remove(path);
            return;
        }
		
		bool nomatch(bool delegate(string) dg){
			foreach (ref rule; bypass_rules) {
				if( dg(rule) ) {
					return true;
				};
			}
			foreach(ref ir; iRedir.list ) {
				if( dg(ir.ip) ) {
					return true;
				};
			}
			return false ;
		}

        formattedWrite(writer, "ipset create gfwset hash:net\n");
		bool[string] nomatch_skiped ;
        foreach (ref rule; proxy_rules) {
			if(nomatch((string subnet){
				if( subnet == rule ) {
					nomatch_skiped[subnet] = true ;
					return true ;
				}
				return false ;
			})) {
				continue ;
			}
            formattedWrite(writer, "ipset add gfwset %s\n", rule);
        }
        formattedWrite(writer, "ipset add gfwset 127.0.0.1/8 nomatch\n");
        formattedWrite(writer, "ipset add gfwset %s/24 nomatch\n", lan_ip);
		nomatch((string subnet){
			if( !(subnet in nomatch_skiped) ) {
	            formattedWrite(writer, "ipset add gfwset %s nomatch\n", subnet);
			}
			return false;
		});
		/*
        foreach (ref proxy; free_proxies) {
			if( !proxy.is_lazy_proxy ){
	            formattedWrite(writer, "ipset add gfwset %s nomatch\n", proxy.server);
			}
        }
		*/
        auto tcp_proxy_port = default_proxy.local_port;
        auto udp_proxy_port = udp_proxy.local_port;

        foreach(ref ir; iRedir.list ) {
          if( ir.redirs.length is 0 ) {
            formattedWrite(
                writer, "iptables -t nat -A prerouting_rule -i br-lan -p tcp -d %s --dport 80 -j DNAT --to-destination %s:8080\n",
                ir.ip, ir.ip);
            formattedWrite(
                writer, "iptables -t nat -A prerouting_rule -i br-lan -p tcp -d %s --dport 443 -j DNAT --to-destination %s:8443\n",
                ir.ip, ir.ip);
          } else {
            foreach(ushort ir_port, ref IP ir_ip; ir.redirs) {
                formattedWrite(
                  writer, "iptables -t nat -A prerouting_rule -i br-lan -p tcp -d %s --dport %s -j DNAT --to-destination %s:%s\n",
                  ir.ip, ir_port,  ir_ip.ip, ir_ip.port);
            }
          }
        }
        
        formattedWrite(writer, "iptables -t nat -N %s\n", nat_chain);
        formattedWrite(writer,
            "iptables -t nat -A %s -p tcp -m set --match-set gfwset dst -j REDIRECT --to-ports %s\n",
            nat_chain, tcp_proxy_port);
        formattedWrite(writer, "iptables -t nat -I zone_lan_prerouting 1 -p tcp -j %s\n", nat_chain);

        if (use_udp_forward) {
            formattedWrite(writer, "iptables -t filter -N %s\n", forward_chain);
            formattedWrite(writer, "iptables -t filter -A %s -p udp -j ACCEPT\n", forward_chain,
                lan_ip);
            formattedWrite(writer, "iptables -t filter -I forwarding_rule 1 -p udp -j %s\n",
                forward_chain);
        }

        if (use_udp_forward || use_udp_output) {
            formattedWrite(writer, "iptables -t nat -N %s\n", udp_chain);
        }
        if (use_udp_output) {
            formattedWrite(writer,
                "iptables -t nat -A %s -p udp -m set --match-set gfwset dst -j REDIRECT --to-ports %s\n",
                udp_chain, udp_proxy_port);
        }
        if (use_udp_forward) {
            formattedWrite(writer,
                "iptables -t nat -A %s -p udp -m set --match-set gfwset dst -j SNAT --to-source %s\n",
                udp_chain, lan_ip);
        }

        if (use_output) {
            formattedWrite(writer, "iptables -t nat -I OUTPUT 1 -p tcp -m owner --uid-owner %s -j %s\n", _G.sudo_user, nat_chain);
            if (use_udp_output) {
                formattedWrite(writer, "iptables -t nat -I OUTPUT 1 -p udp -j %s\n", udp_chain);
            }
            if (use_udp_forward) {
                formattedWrite(writer, "iptables -t nat -I INPUT 1 -p udp -j %s\n", udp_chain);
            }
        }

        if (use_tproxy) {
            formattedWrite(writer, "ip rule add fwmark 0x01/0x01 table 100\n");
            formattedWrite(writer, "ip route add local 0.0.0.0/0 dev lo table 100\n");
            formattedWrite(writer, "iptables -t mangle -N %s\n", tproxy_chain);
            formattedWrite(
                writer, "iptables -t mangle -A %s -p udp -m set --match-set gfwset dst -j TPROXY --on-port \"%s\" --tproxy-mark 0x01/0x01\n",
                tproxy_chain, udp_proxy_port);
            formattedWrite(writer,
                "iptables -t mangle -I PREROUTING 1 -i br-lan -p udp -j %s\n", tproxy_chain);
        }

        if (adbyby_enable) {
            formattedWrite(writer,
                "iptables -t nat -A zone_lan_prerouting -p tcp --dport 80 -j REDIRECT --to-ports 8118\n");
        }

        if (!path.exists || writer.data != path.readText) {
            std.file.write(path, writer.data);
            if (!proxy_flushed) {
                writefln(">>>: reload iptables");
                do_flush();
            }
            Exec("/bin/sh " ~ path, true, true);
        }
    }
}

static _Environment _G;

void main(string args[]) {
    int start = 2;
    int stop = 2;
    int free = 0;
    int force = 0;
    int verbose = 0;
    foreach (ref argv; args[1 .. $]) {
        if ("-i" == argv || "--free" == argv  || "--ifree" == argv) {
            free = 1;
        }
        if ("-v" == argv || "--verbose" == argv) {
            verbose = 1;
        }
        if ("--force" == argv || "-f" == argv ) {
            force = 1;
        }
        if ("--start" == argv) {
            start = 1;
        }
        if ("--stop" == argv) {
            stop = 1;
        }
        if ("-r" == argv || "--restart" == argv) {
            start = 1;
            stop = 1;
        }
    }

    if (start is 1) {
        if (stop is 2)
            stop = 0;
    }
    if (stop is 1) {
        if (start is 2)
            start = 0;
    }

    if (force) {
        _G.force_reload = true;
    }
    _G.verbose = verbose ? true : false;
	
	if( verbose ) {
		writefln("start=%s, stop=%s, free=%s, force=%s", start, stop, free, force);
	}

    _G.Init;
    _G.InitPorc;

    if ( force ) {
        if (stop > 0) {
          _G.Exec("killall -9 ss-redir", false);
          _G.Exec("killall -9 ss-redir-udp", false);
          _G.Exec("killall -9 ss-tunnel", false);
          _G.Exec("killall -9 ss-server", false);
          _G.Exec("killall -9 ss-local", false);
          _G.Exec("killall -9 adbyby", false);
          Thread.sleep(dur!("msecs")(50));
        }
	} 
	
	if( !free ){
        if ( stop > 0 ) {
            _G.stop;
            Thread.sleep(dur!("msecs")(50));
		}
        if (start > 0) {
            _G.start;
        }
	}

    if ( free ) {
        if ( stop > 0 ) {
            _G.stop(true);
            Thread.sleep(dur!("msecs")(50));
        }
        _G.InitPorc(true);
        Thread.sleep(dur!("msecs")(50));
        if (start > 0) {
            _G.start(true);
        }
    }
}
