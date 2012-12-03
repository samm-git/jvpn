#!/usr/bin/perl

# Script to run ncsvc without JAVA gui and web browser

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
use Expect;

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
my $username=$Config{"username"};
my $realm=$Config{"realm"};
# debug, set to 1 to enable
my $dnsprotect=$Config{"dnsprotect"};
my $debug=$Config{"debug"};
my $verifycert=$Config{"verifycert"};

# checking if we running under root

my $is_setuid = 0;
if (-e "./ncui") {
	my $mode = (stat("./ncui"))[2];
	$is_setuid = ($mode & S_ISUID) && ((stat("./ncui"))[4]== 0);
	if(!-x "./ncui"){
		print "./ncui is not executable, exiting\n"; 
		exit 1;
	}
}
if( $> != 0 && !$is_setuid) {
	print "Please, run this script with su/sudo or set suid attribute on 'ncui'\n";
	exit 1;
}

$is_setuid = 0;
if (-e "./ncsvc") {
	my $mode = (stat("./ncsvc"))[2];
	$is_setuid = ($mode & S_ISUID) && ((stat("./ncsvc"))[4]== 0);
	if(!-x "./ncsvc"){
		print "./ncsvc is not executable, exiting\n"; 
		exit 1;
	}
}
if( $> != 0 && !$is_setuid) {
	print "Please, run this script with su/sudo or set suid attribute on 'ncsvc'\n";
	exit 1;
}

my $ua = LWP::UserAgent->new;
# on RHEL6 ssl_opts is not exists
if(defined &LWP::UserAgent::ssl_opts) {
    $ua->ssl_opts('verify_hostname' => $verifycert);
}
$ua->cookie_jar({});
push @{ $ua->requests_redirectable }, 'POST';

print "Enter AD/LDAP password: ";
my $password=read_password();
print "\n";

my $response_body = '';

my $res = $ua->post("https://$dhost:$dport/dana-na/auth/url_default/login.cgi",
	[ btnSubmit   => 'Sign In',
	  password  => $password,
	  realm => $realm,
	  tz_offset   => 60,
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
	if ($response_body =~ /name="frmLogin"/) {
		$response_body =~ m/name="key" value="([^"]+)"/;
		my $key=$1;
		print  "The server requires that you enter an additional token ".
			"code to verify that your credentials are valid.\n".
			"To continue, wait for the token code to change and ".
			"then enter the new pin and code.\n";
		
		print "Enter RSA PIN: ";
		my $rsa_password=read_password();
		print "\n";
		my $res = $ua->post("https://$dhost:$dport/dana-na/auth/url_default/login.cgi",
			[ btnSubmit   => 'Sign In',
			  'password#2'  => $rsa_password,
			  key  => $key,
			]);
		$response_body=$res->decoded_content;

	}
	# active sessions found
	if ($response_body =~ /id="DSIDConfirmForm"/) {
		$response_body =~ m/name="FormDataStr" value="([^"]+)"/;
		print "Active sessions found, reconnecting...\n";
		my $res = $ua->post("https://$dhost:$dport/dana-na/auth/url_default/login.cgi",
			[ btnContinue   => 'Continue the session',
			FormDataStr  => $1,
			]);
		$response_body=$res->decoded_content;
		
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
		print "Invalid username or password, exiting \n";
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

# flush after every write
$| = 1;

unless (-e "./ssl.crt" )
{
    system("echo | openssl s_client -connect ${dhost}:${dport} 2>&1 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -outform der > ssl.crt");
}

if (!-e "./ncui") {
	$res = $ua->get ("https://$dhost:$dport/dana-cached/nc/ncLinuxApp.jar",':content_file' => './ncLinuxApp.jar');
	print "Client not exists, downloading from https://$dhost:$dport/dana-cached/nc/ncLinuxApp.jar\n";
	if ($res->is_success) {
		system("unzip ncLinuxApp.jar libncui.so ncsvc");
		print "Done, extracting\n";
		system("gcc -m32 -Wl,-rpath,`pwd` -o ncui libncui.so");
		print "Done, building ncui\n";
		system("chmod +x ./ncui ./ncsvc");
	}
	else {
		print "Download failed, exiting\n";
		exit 1;
	}
}
my $start_t = time;
#system("LD_LIBRARY_PATH=./ ./ncui -h $dhost -c DSID=$dsid -f ssl.crt");
my $exp = Expect->spawn("LD_LIBRARY_PATH=./ ./ncui -h $dhost -c DSID=$dsid -f ssl.crt") or die "Cannot spawn ncui: $!\n";;
$exp->log_stdout(0);
my $spawn_ok;
my $timeout=undef;
$exp->expect($timeout,
	     [
	      qr'Password: $',
	      sub {
		  $spawn_ok = 1;
		  my $fh = shift;
		  $fh->send("$password\n");
		  print "Connected to $dhost $realm...Ctrl-C will exit.\n";
		  exp_continue;
	      } 
	     ],
	     [
	      eof =>
	      sub {
		  if ($spawn_ok) {
		      die "ERROR: premature EOF in login.\n";
		  } else {
		      die "ERROR: could not spawn telnet.\n";
		  }
	      }
	     ],
	     [
	      timeout =>
	      sub {
		  die "No login.\n";
	      }
	     ],
	     '-re', qr'[#>:] $', #' wait for shell prompt, then exit expect
    );

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
	print "Logging out...\n";
	# do logout
	$ua -> get ("https://$dhost:$dport/dana-na/auth/logout.cgi");
	print "Killing ncui...\n";
	# it is suid, so best is to use own api
	system("pkill ncui");
	# checking if resolv.conf correctly restored
	if(-f "/etc/jnpr-nc-resolv.conf"){
	    print "restoring resolv.conf\n";
	    move("/etc/jnpr-nc-resolv.conf","/etc/resolv.conf");
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

sub read_password {
	my $password = "";
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
		"Report jvpn bugs to alevy\@mobitv.com\n";
	exit 0;
}


