#!/usr/bin/env rdmd

import  std.array, std.conv, std.stdio, std.format, std.string;


void main(string[] args){
	if( args.length < 3 ) {
		writefln("useage: %s ip1,ip2  port1,port3  [maxconn] ", args[0]);
		return ;
	}
	auto maxconn	= 0 ;
	if( args.length > 3 ) {
		maxconn	= to!int(args[3]);
	}
	if( maxconn < 128 || maxconn > 20480 ) {
		maxconn	= 1024 * 8 ;
	}
	auto ips = split(args[1], ',') ;
	auto ports = split(args[2], ',') ;
	
	auto index	= 0 ;
	foreach(port; ports){
		foreach(int i, ref ip; ips){
			index++ ;
			writefln("   server server%d_%s %s:%s maxconn %d weight 1", i, index,  ip, port, maxconn);
		}
	}
}