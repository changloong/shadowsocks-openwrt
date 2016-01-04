module dcd.wrapper ;

import core.sys.posix.unistd;
import core.sys.posix.pwd;
import core.memory;
import std.process;
import std.stdio;
import std.file;
import std.conv;
import std.range;

import
	std.array,
	std.format,
	std.experimental.logger;

static dcd_server	= "/opt/local/bin/dcd-server" ;
static dcd_client	= "/opt/local/bin/dcd-client" ;
static dcd_config	= "~/.config/dcd/dcd.conf" ;

void check(ref string[] args){
	if( args.length > 1 ) {
		args[0] = dcd_client ;
	} else {
		args[0] = dcd_server ;
	    auto config_path	= std.path.expandTilde(dcd_config) ;
	    if( config_path[0] is '~' ) {
            auto pw = getpwuid(getuid());
            auto home = to!string(pw.pw_dir) ;
            config_path = home ~ dcd_config[1..$] ;
	    }
        if( std.file.exists(config_path) ) {
            scope config_file	= std.stdio.File(config_path);
            foreach(ref line; config_file.byLine) {
                auto path = std.string.strip( cast(string) line) ;
                if( path !is null && path.length > 0 ) {
                    args    ~= "-I" ;
                    args    ~=  escapeShellFileName(path) ;
                }
            }
        }
	}
    args    ~= "-p19166" ;
}

void main(string[] args){
    check(args) ;
    if( dcd_server == args[0] ) {
        auto _args  = new string[ 3 ] ;
        _args[0]    = "/bin/sh" ;
        _args[1]    = "-c" ;
        _args[2]    = join(args, ' ') ~ " >/tmp/dcd_server.log 2>&1" ;
        execv(_args[0], _args);
    } else {
        execv(args[0], args);
    }
}
