<?php


$filters = getChinaRoutes( 1 ) ;

$worlds	= getWorldRoutes($filters, 1 );





function getWorldRoutes( $filters ,  $print ) {
	$tag	= 'unknow' ;
	$array  = array() ;
	
	$exists	= function($subnet) use( & $filters ) {
		list($ip, $bits) = explode('/', $subnet) ;
		$min = ip2long($ip) & ( -1 << (32 - $bits) ) ;
		$max = ($min | ( 1 << (32 - $bits) )-1) ;
		foreach($filters as $from => $to ) {
			if( $min >= $from && $max <= $to ) {
				return true ;
			}
		}
		// echo long2ip($min), " -> ", long2ip($max), "  -> $ip/$bits \n" ;
	} ;
	
	foreach( file( __DIR__ . '/world.ini') as $ln ) {
		$ln = trim($ln) ;
		if( empty($ln) ) continue ;
		$pos = strpos($ln, ';') ;
		if( false !== $pos ) {
			if( 0 === $pos ) {
				continue ;
			}
			$ln = trim( substr($ln, $pos ) ) ;
			if( empty($ln) ) continue ;
		}
		$pos = strpos($ln, '[') ;
		if( false !== $pos ) {
			$_pos	= strrpos($ln, ']', 1 ) ;
			if( $_pos == false ) {
				$_pos = strlen($ln) ;
			} else {
				$_pos = $_pos - 1 ;
			}
			$tag	= substr($ln, $pos + 1 , $_pos - $pos ) ;
			continue ;
		}
		if( !$exists($ln) ) {
			$array[ $tag ][] = $ln ;
		}
	}
	
	foreach($array as $tag => $_array) {
		echo ";$tag\n";
		foreach($_array as $ln) {
			echo "$ln\n";
		}
	}
}


function getChinaRoutes( $print ){
	$china	= file( __DIR__ . '/china.ini') ;
	$map = array() ;
	for($i = 1; $i <=254 ; $i++) {
		$map[$i] = $i ;
	}
	$_map = array_keys($map);
	$skiped = array() ;

	foreach($china as $ln) {
		$ln	= trim($ln);
		if( empty($ln) ) continue ;
		$ln = explode('/', $ln);
		$ip = $ln[0] ;
		$subnet = $ln[1] ;
		$_ln	= explode('.', $ip);
		$i =  (int) ($_ln[0]) ;
		if( isset($map[$i]) ) {
			unset($map[$i]) ;
			$skiped[$i] = array(); 
			$skiped[$i][] = array($ip, $subnet);
		} else {
			$skiped[$i][] = array($ip, $subnet);
		}
	}

	$has = false ;
	$from = 1 ;
	$results = array() ;
	

	$find = function ($from, $to ) use ( & $results , $print ) {
	
		$_to	= ip2long("$to.255.255.255") ;
		for( $i = $from ; $i < $to ; $i++ ) {
			$_from  = ip2long("$i.0.0.0");
			for( $bits = 1 ; $bits <= 8  ; $bits++ ) {
				$min = $_from & ( -1 << (32 - $bits) ) ;
				$max = ($min | ( 1 << (32 - $bits) )-1) ;
				if( $min < $_from ) {
					continue ;
				}
				if( $max > $_to ) {
					continue ;
				}
				$_min = long2ip($min) ;
				$_max = long2ip($max) ;
				$_stop = explode('.', $_max);
				$_stop = (int) $_stop[0] ;
				$results[ $min ] =  $max ; 
				if( $print ) echo "$i.0.0.0/$bits\n";
				for( $j = $i + 1 ; $j <= $_stop; $j++ ){
					if( $print ) echo ";$j.0.0.0/8\n";
				}
				$i	= $_stop ;
				break ;
			}
		} 
	} ;


	foreach($_map  as $i) {
		$last = $i - 1 ;
		if( $has ) {
			if( !isset($map[$i]) ) {
				$has = false ;
				$find($from, $last) ;
				$from  = $i ;
			}
		} else {
			if( isset($map[$i]) ) {
				$has = true ;
				// echo "; * $from -> $last \n";
				$from  = $i ;
			}
		}
	}
	return $results ;
}







