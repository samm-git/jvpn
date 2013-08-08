#!/usr/bin/perl

# Script to run ncsvc without JAVA gui and web browser

# The author has placed this work in the Public Domain, thereby relinquishing
# all copyrights. Everyone is free to use, modify, republish, sell or give away
# this work without prior consent from anybody.

# This software is provided on an "as is" basis, without warranty of any
# kind. Use at your own risk! Under no circumstances shall the author(s) or
# contributor(s) be liable for damages resulting directly or indirectly from
# the use or non-use of this software.


use strict;
use warnings;
use Term::ReadKey;
use IO::Socket::INET;
use Fcntl ':mode';
use Getopt::Long;
use HTTP::Request::Common;
use LWP::UserAgent;
use HTTP::Cookies;
use File::Copy;
use File::Temp;
use File::Path;
use POSIX;

my %Config;
my $config_file='jvpn.ini';
my $show_help=0;

GetOptions ("config_file=s" => \$config_file,
	"help" => \$show_help);

if($show_help) { print_help(); }

# parse configuration
&parse_config_file ($config_file, \%Config);

my $dhost=$Config{"host"};
my $dport=$Config{"port"};
my $durl=$Config{"url"};
my $username=$Config{"username"};
my $realm=$Config{"realm"};
# debug, set to 1 to enable
my $dnsprotect=$Config{"dnsprotect"};
my $debug=$Config{"debug"};
my $verifycert=$Config{"verifycert"};
my $mode=$Config{"mode"};
my $script=$Config{"script"};
my $cfgpass=$Config{"password"};
my $password="";
my $hostchecker=$Config{"hostchecker"};
my $tncc_pid = 0;

# check mode
if(defined $mode){
	if($mode !~ /^nc(ui|svc)$/) {
		print "Configuration error: mode is set incorrectly ($mode), check jvpn.ini\n";
		exit 1;
	}
}
else { $mode="ncsvc"; }

# check password method
if(defined $cfgpass){
	if($cfgpass !~ /^(interactive|helper:|plaintext:)/) {
		print "Configuration error: password is set incorrectly ($cfgpass), check jvpn.ini\n";
		exit 1;
	}
}
else { $cfgpass="interactive"; }

# set host checker mode
$hostchecker=0 if !defined($mode);
# set default url if needed
$durl = "url_default" if (!defined($durl));

# checking if we running under root
# we need ncsvc to be uid for all modes
my $is_setuid = 0;
if (-e "./ncsvc") {
	my $fmode = (stat("./ncsvc"))[2];
	$is_setuid = ($fmode & S_ISUID) && ((stat("./ncsvc"))[4] == 0);
	if(!-x "./ncsvc"){
		print "./ncsvc is not executable, exiting\n"; 
		exit 1;
	}
}

if( $> != 0 && !$is_setuid) {
	print "Please, run this script with su/sudo or set suid attribute on $mode \n";
	exit 1;
}

my $ua = LWP::UserAgent->new;
# on RHEL6 ssl_opts is not exists
if(defined &LWP::UserAgent::ssl_opts) {
    $ua->ssl_opts('verify_hostname' => $verifycert);
}
$ua->cookie_jar({});
push @{ $ua->requests_redirectable }, 'POST';

# if Juniper VPN server finds some 'known to be smart' useragent it will try to start
# "host checker" service on a client machine using Java applet.
if ($hostchecker) {
    $ua->agent('Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:23.0) Gecko/20100101 Firefox/23.0');
    # emulate javascript java check result
    $ua->cookie_jar->set_cookie(0,"DSCheckBrowser","java","/",$dhost,$dport,1,1,60*5,0, ());
}
else {
    $ua->agent('JVPN/Linux');
}
# show LWP traffic dump if debug is enabled
if($debug){
    $ua->add_handler("request_send",  sub { shift->dump; return });
    $ua->add_handler("response_done", sub { shift->dump; return });
}

if ($cfgpass eq "interactive") {
	print "Enter PIN+password: ";
	$password=read_password();
	print "\n";
}
elsif ($cfgpass =~ /^plaintext:(.+)/) {
	print "Using user-defined password\n";
	$password=$1;
	chomp($password);
}
elsif ($cfgpass =~ /^helper:(.+)/) {
	print "Using user-defined script to get the password\n";
	$password=run_pw_helper($1);
}

my $response_body = '';

my $res = $ua->post("https://$dhost:$dport/dana-na/auth/$durl/login.cgi",
	[ btnSubmit   => 'Sign In',
	password  => $password,
	realm => $realm,
	tz   => '60',
	username  => $username,
	]);

$response_body=$res->decoded_content;
my $dsid="";
my $dlast="";
my $dfirst="";

# Looking at the results...
if ($res->is_success) {
	print("Transfer went ok\n");
	# next token request
	if ($response_body =~ /name="frmNextToken"/) {
		$response_body =~ m/name="key" value="([^"]+)"/;
		my $key=$1;
		print  "The server requires that you enter an additional token ".
			"code to verify that your credentials are valid.\n".
			"To continue, wait for the token code to change and ".
			"then enter the new pin and code.\n";
		
		# if password was specified in plaintext we should not use it 
		# here, it will not work anyway
		if ($cfgpass eq "interactive" || $cfgpass =~ /^plaintext:/) {
			print "Enter PIN+password: ";
			$password=read_password();
			print "\n";
		}
		elsif ($cfgpass =~ /^helper:(.+)/) {
			print "Using user-defined script to get the password\n";
			# set current password to the OLDPIN variable to make 
			# helper aware that we need a new key
			$ENV{'OLDPIN'}=$password;
			$password=run_pw_helper($1);
			delete $ENV{'OLDPIN'}; 
		}
		my $res = $ua->post("https://$dhost:$dport/dana-na/auth/$durl/login.cgi",
			[ Enter   => 'secidactionEnter',
			password  => $password,
			key  => $key,
			]);
		$response_body=$res->decoded_content;
	}
	# active sessions found
	if ($response_body =~ /id="DSIDConfirmForm"/) {
		$response_body =~ m/name="FormDataStr" value="([^"]+)"/;
		print "Active sessions found, reconnecting...\n";
		my $res = $ua->post("https://$dhost:$dport/dana-na/auth/$durl/login.cgi",
			[ btnContinue   => 'Continue the session',
			FormDataStr  => $1,
			]);
		$response_body=$res->decoded_content;
	}
	# hostchecker authorization stage
	if($hostchecker) {
		if(!-e "./tncc.jar") { # download tncc.jar if not exists
			print "tncc.jar does not exist, downloading from https://$dhost:$dport/dana-cached/hc/tncc.jar\n";
			my $resdl = $ua->get ("https://$dhost:$dport/dana-cached/hc/tncc.jar",":content_file" => "./tncc.jar");
			if (!$resdl->is_success) {
				print "Unable to download tncc.jar, exiting \n";
				exit 1;
			}
		}
		# get state id and check if we on a right page
		my $state_id='';
		# sample base https://vpn.com/dana-na/auth/url_default/welcome.cgi?p=preauth&id=state_c63757c951e0050e6d9f22ef13442&signinRealmId=4
		if ( $res->base =~ /[&?]id=(state_[0-9a-f]+)/){
			$state_id=$1;
		}
		else {
			print "Unable to get preauth id\n";
			exit 1;
		} # now we got preauth, so lets try to start tncc
		$tncc_pid = tncc_start($res->decoded_content);
		open NARPORT, $ENV{"HOME"}."/.juniper_networks/narport.txt" or die $!; 
		my $narport = <NARPORT>;
		chomp $narport;
		close NARPORT;
		my $narsocket = new IO::Socket::INET (
			PeerHost => '127.0.0.1',
			PeerPort => $narport,
			Proto => 'tcp',
		) or die "ERROR in Socket Creation : $!\n";
		print "TCP Connection to the tncc.jar process established.\n";
		my $dspreauth="";
		my $cookie=$ua->cookie_jar->as_string;
		if ( $cookie =~ /DSPREAUTH=([^;]+)/){
			$dspreauth=$1;
		}
		# sending DSPREAUTH
		print "Sending data to tncc...         ";
		my $data =   "start\nIC=$dhost\nCookie=$dspreauth\nDSSIGNIN=null\n";
		hdump($data) if $debug;
		print $narsocket "$data";
		$narsocket->recv($data,2048);
		$narsocket->close();
		my @resp_lines = split /\n/, $data;

		if($resp_lines[0]!=200) {
			print "\nGot non 200 (".$resp_lines[0].") return code\n";
			exit 1;
		}
		print "[done]\n";
		$ua->cookie_jar->set_cookie(0,"DSPREAUTH",$resp_lines[2],"/dana-na/",$dhost,$dport,1,1,60*5,0, ());
		$ua->get("https://$dhost:$dport/dana-na/auth/url_default/login.cgi?loginmode=mode_postAuth&postauth=$state_id");
	}

	my $cookie=$ua->cookie_jar->as_string;
	if ( $cookie =~ /DSID=([a-f\d]+)/){
		$dsid=$1;
	}
	if ( $cookie =~ /DSFirstAccess=(\d+)/){
		$dfirst=$1;
	}
	if ( $cookie =~ /DSLastAccess=(\d+)/){
		$dlast=$1;
	}
	if ( $response_body =~ /Invalid username or password/){
		print "Invalid user name or password, exiting \n";
		exit 1;
	}
	
	# do not print DSID in normal mode for security reasons
	print $debug?"Got DSID=$dsid, dfirst=$dfirst, dlast=$dlast\n":"Got DSID\n";
	
	if ($dsid eq "" || $dfirst eq "" || $dlast eq "") {
		print "Unable to get data, exiting \n";
		exit 1;
	}
	
} else {
	# Error code, type of error, error message
		print("An error happened: ".$res->status_line."\n");
	exit 1;
}

# set int handlers
$SIG{'INT'}  = \&INT_handler; # CTRL+C
$SIG{'TERM'} = \&INT_handler; # Kill process
$SIG{'HUP'} = \&INT_handler; # Terminal closed
$SIG{'PIPE'} = \&INT_handler; # Process died

# flush after every write
$| = 1;

my $md5hash = '';
my $crtfile = ''; 
my $fh; # should be global or file is unlinked

if($mode eq "ncsvc") {
	$md5hash = <<`	SHELL`;
	echo | openssl s_client -connect ${dhost}:${dport} 2>/dev/null| \
	openssl x509 -md5 -noout -fingerprint|\
	awk -F\= '{print \$2}'|tr -d \:
	exit 0
	SHELL
	chop($md5hash);
	# changing case
	$md5hash =~ tr/A-Z/a-z/;
	if($md5hash eq "") {
		print "Unable to get md5 hash of certificate, exiting";
		exit 1;
	}
	print "Certificate fingerprint:  [$md5hash]\n";
}
elsif($mode eq "ncui") {
	# we need to fetch certificate
	$fh = File::Temp->new();
	$crtfile = $fh->filename;
	<< `	SHELL`;
	echo | openssl s_client -connect ${dhost}:${dport} 2>&1 | \
	sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | \
	openssl x509 -outform der > $crtfile
	SHELL
	printf("Saved certificate to temporary file: $crtfile\n");
}

if (!-e "./$mode") {
	$res = $ua->get ("https://$dhost:$dport/dana-cached/nc/ncLinuxApp.jar",':content_file' => './ncLinuxApp.jar');
	print "Client not exists, downloading from https://$dhost:$dport/dana-cached/nc/ncLinuxApp.jar\n";
	if ($res->is_success) {
		print "Done, extracting\n";
		system("unzip ncLinuxApp.jar ncsvc libncui.so && chmod +x ./ncsvc");
		if($mode eq "ncui") {
			printf "Trying to compile 'ncui'. gcc must be installed to make this possible\n";
			system("gcc -m32 -o ncui wrapper.c -ldl  -Wall 2>&1 >compile.log && chmod +x ./ncui");
			if (!-e "./ncui") {
				printf("Error: Compilation failed, please compile.log\n");
				exit 1;
			}
			else {
				printf("ncui binary compiled\n");
			}
		}
	}
	else {
		print "Download failed, exiting\n";
		exit 1;
	}
}


my $start_t = time;

my ($socket,$client_socket);
my $data;
if($mode eq "ncsvc") {
	system("./ncsvc >/dev/null 2>/dev/null &");
	sleep(3);
	# connecting to ncsvc using TCP
	$socket = new IO::Socket::INET (
		PeerHost => '127.0.0.1',
		PeerPort => '4242',
		Proto => 'tcp',
		) or die "ERROR in Socket Creation : $!\n";

	print "TCP Connection to ncsvc process established.\n";

	# sending first packet, got it from tcpdump
	print "Sending handshake #1 packet... ";
	$data =   "\0\0\0\0\0\0\0\x64\x01\0\0\0\0\0\0\0\0\0\0\0";

	if($debug) {hdump($data);}
	print $socket "$data";
	$socket->recv($data,2048);
	# XXX - good idea to chek if it valid
	print " [done]\n";
	if($debug) {hdump($data);}

	# second packet from tcpdump
	# it contains logging level in the end:
	# 0 LogLevel 0, 10 LogLevel 1, 20 LogLevel 2
	# 30 LogLevel 3, 40 LogLevel 4, 50 LogLevel 5
	# We are enabling full log if debug is enabled
	$data= "\0\0\0\0\0\0\0\x7c\x01\0\0\0\x01\0\0\0\0\0\0\x10\0\0\0\0\0\x0a\0\0".
		"\0\0\0\x04\0\0\0".($debug?"\x32":"\0");
	print "Sending handshake #2 packet... ";
	if($debug) {hdump($data);}
		print $socket "$data";
	$socket->recv($data,2048);
	# XXX - good idea to chek if it is valid
	print " [done]\n";
	if($debug) {hdump($data);}
	my $dsidline="DSSignInURL=/; DSID=$dsid; DSFirstAccess=$dfirst; DSLastAccess=$dlast; path=/; secure";
	# Configuration packet
	# XXX - no idea how it works on non default port
	$data="\0\0\0\0\0\0\0\x66\x01\0\0\0\x01\0\0\0\0\0\0".pack("C*",(length($dhost)+1) + (length($dsidline)+1) + 57)."\0\xcb\0\0".
		"\0".pack("C*",(length($dhost)+1) + (length($dsidline)+1) + 51)."\0\x01\0\0\0".pack("C*",length($dhost)+1).
		$dhost.
		"\0\0\x02\0\0\0".pack("C*",length($dsidline)+1).
		$dsidline.
		"\0\0\x0a\0\0\0".pack("C*",length($md5hash)+1).
		$md5hash.
		"\0";
	print "Sending configuration packet...";
	if($debug) {hdump($data);}
	print $socket "$data";
	$socket->recv($data,2048);
	print " [done]\n";
	if($debug) {hdump($data);}
	# checking reply status
	my @result = unpack('C*',$data);
	my $status = sprintf("%02x",$result[7]);
	# 0x6d seems to be "Connect ok" message
	# exit on any other values
	
	if($status ne "6d") {
		printf("Status=$status\nAuthentication failed, exiting\n");
		system("./ncsvc -K");
		exit(1);
	}
	if($> == 0 && $dnsprotect) {
		system("chattr +i /etc/resolv.conf");
	}

} # ncsvc


if ($mode eq "ncui"){
	print "Starting ncui, this should bring VPN up.\nPress CTRL+C anytime to terminate connection\n";
	my $childpid;
	local $SIG{'CHLD'} = 'IGNORE';
	my @oldlist = get_tap_interfaces();
	my $pid = fork();
	if ($pid == 0) {
		my $args = "./ncui\n-p\n\n".
			"-h\n$dhost\n".
			"-c\nDSSignInURL=/; DSID=$dsid; DSFirstAccess=$dfirst; DSLastAccess=$dlast; path=/; secure\n".
			"-f\n$crtfile\n".
			($debug?"-l\n5\n-L\n5\n":"");
		$debug && print $args;
		open(WRITEME, "|-", "./ncui") or die "Couldn't fork: $!\n";
		print WRITEME $args;
		close(WRITEME);
		printf("ncui terminated\n");
		exit 0;
	}
	my $exists = kill 0, $pid;
	my $vpnint = get_new_tap_interface(\@oldlist, 15);
	if ($vpnint eq '') {
		printf("Error: new interface not found, check ncsvc logs\n");
		INT_handler();
	}
	printf("Connection established, new interface: $vpnint\n");
	if($exists && $> == 0 && $dnsprotect) {
		system("chattr +i /etc/resolv.conf");
	}
	if(defined $script && -x $script){
		print "Running user-defined script\n";
		$ENV{'EVENT'}="up";
		$ENV{'MODE'}=$mode;
		$ENV{'INTERFACE'}=$vpnint;
		system($script);
	}
	
	for (;;) {
	    $exists = kill SIGCHLD, $pid;
	    $debug && printf("\nChecking child: exists=$exists, $pid\n");
	    # printing RX/TX from /proc/net/dev
	    my $now = time - $start_t;
	    open STAT, "/proc/net/dev" or die $!;
	    while (<STAT>) {
	    	    if ($_ =~ m/^\s*${vpnint}:\s*(\d+)(?:\s+\d+){7}\s*(\d+)/) {
	    	    	    print "\r                                                              \r";
	    	    	    printf("Duration: %02d:%02d:%02d  Sent: %s\tReceived: %s", 
	    	    	    	    int($now / 3600), int(($now % 3600) / 60), int($now % 60),
	    	    	    	    format_bytes($2), format_bytes($1));
	    	    }
	    }
	    close(STAT);
	    if(!$exists) {
		INT_handler();
	    }
	    sleep 2;
	}
}

if($mode eq "ncsvc") {
	# information query
	$data =  "\0\0\0\0\0\0\0\x6a\x01\0\0\0\x01\0\0\0\0\0\0\0";
	if($debug) {hdump($data);}
	print $socket "$data";
	$socket->recv($data,2048);
	if($debug) {hdump($data);}

	if(defined $script && -x $script){
		print "Running user-defined script\n";
		$ENV{'EVENT'}="up";
		$ENV{'MODE'}=$mode;
		$ENV{'DNS1'}=inet_ntoa(pack("N",unpack('x[84]N',$data)));
		$ENV{'DNS2'}=inet_ntoa(pack("N",unpack('x[94]N',$data)));
		$ENV{'IP'}=inet_ntoa(pack("N",unpack('x[48]N',$data)));
		$ENV{'GATEWAY'}=inet_ntoa(pack("N",unpack('x[68]N',$data)));
		system($script);
	}
	print "IP: ".inet_ntoa(pack("N",unpack('x[48]N',$data))).
		" Gateway: ".inet_ntoa(pack("N",unpack('x[68]N',$data))).
		"\nDNS1: ".inet_ntoa(pack("N",unpack('x[84]N',$data))).
		"  DNS2: ".inet_ntoa(pack("N",unpack('x[94]N',$data))).
		"\nConnected to $dhost, press CTRL+C to exit\n";
	# disabling cursor
	print "\e[?25l";
	while ( 1 ) {
		#stat query
		$data="\0\0\0\0\0\0\0\x69\x01\0\0\0\x01\0\0\0\0\0\0\0";
		print "\r                                                              \r";
		if($debug) {hdump($data);}
		print $socket "$data";
		$socket->recv($data,2048);
		if(!length($data) || !$socket->connected()) {
		    print "No response from ncsvc, closing connection\n";
		    INT_handler();
		}
		if($debug) {hdump($data);}
		my $now = time - $start_t;
		# printing RX/TX. This packet also contains encription type,
		# compression and transport info, but length seems to be variable
		printf("Duration: %02d:%02d:%02d  Sent: %s\tReceived: %s", 
			int($now / 3600), int(($now % 3600) / 60), int($now % 60),
			format_bytes(unpack('x[78]N',$data)), format_bytes(unpack('x[68]N',$data)));
		sleep(1);
	}

	print "Exiting... Connect failed?\n";
	
	$socket->close();
} # mode ncsvc loop

# for debugging
sub hdump {
	my $offset = 0;
	my(@array,$format);
	foreach my $data (unpack("a16"x(length($_[0])/16)."a*",$_[0])) {
		my($len)=length($data);
		if ($len == 16) {
			@array = unpack('N4', $data);
			$format="0x%08x (%05d)   %08x %08x %08x %08x   %s\n";
		} else {
			@array = unpack('C*', $data);
			$_ = sprintf "%2.2x", $_ for @array;
			push(@array, '  ') while $len++ < 16;
			$format="0x%08x (%05d)" .
				"   %s%s%s%s %s%s%s%s %s%s%s%s %s%s%s%s   %s\n";
			
		} 
		$data =~ tr/\0-\37\177-\377/./;
		printf $format,$offset,$offset,@array,$data;
		$offset += 16;
	}
}

# handle ctrl+c to logout and kill ncsvc 
sub INT_handler {
	# de-register handlers
	$SIG{'INT'} = 'DEFAULT';
	$SIG{'TERM'} = 'DEFAULT';
	$SIG{'HUP'} = 'DEFAULT';
	# re-enabling cursor
	print "\e[?25h";
	if($> == 0 && $dnsprotect) {
		system("chattr -i /etc/resolv.conf");
	}
	if($mode eq "ncsvc" && $socket->connected()){
	    print "\nSending disconnect packet\n";
    	    # disconnect packet
	    $data="\0\0\0\0\0\0\0\x67\x01\0\0\0\x01\0\0\0\0\0\0\0";
	    if($debug) {hdump($data);}
	    print $socket "$data";
	    $socket->recv($data,2048);
	    print "Got reply\n";
	    # xxx - we are ignoring reply
	    if($debug) {hdump($data);}
	}
	print "Logging out...\n";
	# do logout
	$ua -> get ("https://$dhost:$dport/dana-na/auth/logout.cgi");
	print "Killing ncsvc...\n";
	# it is suid, so best is to use own api
	system("./ncsvc -K");

	# checking if resolv.conf correctly restored
	if(-f "/etc/jnpr-nc-resolv.conf"){
	    print "restoring resolv.conf\n";
	    move("/etc/jnpr-nc-resolv.conf","/etc/resolv.conf");
	}
	if(defined $script && -x $script){
		print "Running user-defined script\n";
		$ENV{'EVENT'}="down";
		$ENV{'MODE'}=$mode;
		system($script);
	}
	# hostchecker cleanup
	if($hostchecker) {
		kill 'KILL', $tncc_pid if $tncc_pid;
		unlink $ENV{"HOME"}."/.juniper_networks/narport.txt" if -e $ENV{"HOME"}."/.juniper_networks/narport.txt";
	}
	print "Exiting\n";
	exit(0);
}

sub parse_config_file {
	
	my $Name,my $Value; my $Config; my $File;
	
	($File, $Config) = @_;
	
	if (!open (CONFIG, "$File")) {
		print "ERROR: Config file not found : $File\n";
		exit(1);
	}
	
	while (<CONFIG>) {
		my $config_line=$_;
		chop ($config_line);          # Get rid of the trailling \n
		
		$config_line =~ s/^\s*//;     # Remove spaces at the start of the line
		$config_line =~ s/\s*$//;     # Remove spaces at the end of the line
		if ( ($config_line !~ /^#/) && ($config_line ne "") ){    # Ignore lines starting with # and blank lines
			($Name, $Value) = split (/=/, $config_line);          # Split each line into name value pairs
			$$Config{$Name} = $Value;                             # Create a hash of the name value pairs
		}
	}
	
	close(CONFIG);
	
}

sub run_pw_helper {
	my $pw_script="";
	($pw_script) = @_;
	if (-x $pw_script){
		$password=`$pw_script`;
		chomp $password
	}
	return $password;
}

sub tncc_start {
	my $body="";
	($body) = @_;
	my @lines = split "\n", $body;
	my %params = ();
	# read applet params from the page
	foreach my $line (@lines) {
		if ( $line =~ /NAME="([^"]+)"\s+VALUE="([^"]+)"/){
			$params{ $1 } = $2;
		}
	}
	# FIXME add some param validation
	# create directory for logs if not exists
	mkpath($ENV{"HOME"}."/.juniper_networks/network_connect") if !-e $ENV{"HOME"}."/.juniper_networks/network_connect";
	# just in case. Should we also kill all tncc.jar processes?
	unlink $ENV{"HOME"}."/.juniper_networks/narport.txt";
	my $pid = fork();
	if ($pid == 0) {
		my @cmd = ("java");
		push @cmd, "-classpath", "./tncc.jar";
		push @cmd, "net.juniper.tnc.HttpNAR.HttpNAR";
		push @cmd, "loglevel", $params{'log_level'};
		push @cmd, "postRetries", $params{'postRetries'};
		push @cmd, "ivehost", $params{'ivehost'};
		push @cmd, "Parameter0", $params{'Parameter0'};
		push @cmd, "locale", $params{'locale'};
		push @cmd, "home_dir", $ENV{'HOME'};
		push @cmd, "user_agent", $params{'HTTP_USER_AGENT'};
		system(@cmd);
		exit;
	}
	for(my $i = 0; $i < 10; $i++) {
		last if(-e $ENV{"HOME"}."/.juniper_networks/narport.txt");
		sleep 1;
	}
	die("Unable to start tncc.jar") if !-e $ENV{"HOME"}."/.juniper_networks/narport.txt";
	return $pid;
}

sub read_password {
	$password = "";
	my $pkey="";
	# Start reading the keys
	ReadMode(4); #Disable the control keys
	while(ord($pkey = ReadKey(0)) != 10)
	# This will continue until the Enter key is pressed (decimal value of 10)
	{
		# For all value of ord($key) see http://www.asciitable.com/
		if(ord($pkey) == 127 || ord($pkey) == 8) {
			# DEL/Backspace was pressed
			#1. Remove the last char from the password
			
			#2 move the cursor back by one, print a blank character, move the cursor back by one
			if (length($password)) {
				print "\b \b";
			}
			chop($password);
		} elsif(ord($pkey) < 32) {
			# Do nothing with these control characters
		} else {
			$password = $password.$pkey;
			print "*";
		}
	}
	ReadMode(0); #Reset the terminal once we are done
	return $password;
}

sub print_help {
	print "Usage: $0 [--config <filename>] [-h]\n".
		"\t-c, --config         configuration file, default jvpn.ini\n".
		"\t-h, --help           print this text\n".
		"Report jvpn bugs to samm\@os2.kiev.ua\n";
	exit 0;
}

# i don`t want CPAN hell
sub format_bytes
{
	my ($size) = @_;
	
	if ($size > 1099511627776)  #   TiB: 1024 GiB
	{
		return sprintf("%.2f TiB", $size / 1099511627776);
	}
	elsif ($size > 1073741824)  #   GiB: 1024 MiB
	{
		return sprintf("%.2f GiB", $size / 1073741824);
	}
	elsif ($size > 1048576)     #   MiB: 1024 KiB
	{
		return sprintf("%.2f MiB", $size / 1048576);
	}
	elsif ($size > 1024)        #   KiB: 1024 B
	{
		return sprintf("%.2f KiB", $size / 1024);
	}
	else                        #   B
	{
		return sprintf("%.2f B", $size);
	}
}

sub get_tap_interfaces
{
	my @intlist;
	open FILE, "/proc/net/dev" or die $!; 
	while (my $line = <FILE>){
		if($line =~ /^\s*(tun[0-9]+):/) {
			push(@intlist, $1);
		}
	}
	return @intlist;
}

sub get_new_tap_interface
{
	my (@newints, $i);
	my ($oldint, $timeout) = @_;
	for($i = 0; $i < $timeout; $i++) {
		@newints = get_tap_interfaces();
		foreach my $tunint (@newints) {
			if ( !grep { $_ eq $tunint} @$oldint ) {
				return $tunint;
			}
		}
		sleep(1);
	}
	return '';
}
