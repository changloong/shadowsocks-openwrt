#!/usr/bin/env rdmd

import 
	std.stdio,
	std.file,
	std.json,
	std.process;

version(DEV){
	import 
	std.array,
	std.format,
	std.experimental.logger;
}

static one_time_auth	= "-A" ;
static verbose_mode	= "-v" ;
static ss_local	= "/opt/local/bin/ss-local" ;
static ss_method	= "-m" ;
static ss_method_chacha20	= "chacha20" ;

void check(ref string[] args){
	bool	has_one_time_auth = false ;
	bool	has_verbose_mode = false ;
	string config_file	= null ;
    foreach(int i, ref arg; args){
		if( arg == "-c" ) {
			if( i+1 < args.length ) {
				config_file	= args[i+1] ;
			}
		} else if( arg == one_time_auth ) {
			has_one_time_auth = true ;
		} else if( arg == verbose_mode ) {
			has_verbose_mode	= true ;
		}
    }
	if( config_file ) {
		scope data	= readText(config_file);
		scope j = parseJSON(data);
		if( j.type is JSON_TYPE.OBJECT ) {
			scope method	= j["method"] ;
			if( method.type is JSON_TYPE.STRING ) {
				if( "table" == method.str ) {
					args	~= ss_method ;
					args	~= ss_method_chacha20 ;
					args    ~= "-b" ;
					args    ~= "0.0.0.0" ;
					has_one_time_auth	= true ;
				}
			}
		}
	}
	if( has_one_time_auth ) {
		args ~= one_time_auth ;
	}
	if( !has_verbose_mode ) {
		args ~= verbose_mode ;
	}
	version(DEV){
		auto log	= new FileLogger("/tmp/goagentx.log");
		auto writer = appender!string();
		formattedWrite(writer, "args: %s\n", args);
		formattedWrite(writer, "config: %s\n", readText(config_file));
		log.log(writer.data);
	} 
	
}

int main(string[] args){
	args[0]	= ss_local ;
	check(args);
	return execv(ss_local, args);
}

