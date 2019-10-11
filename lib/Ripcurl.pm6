unit module Ripcurl;
use NativeCall;
use LibCurl::Easy;
use Readline;
use Base64::Native;

enum FUZZMODE is export <FUZZURL FUZZPOST FUZZMIME FUZZHEADER> ;
enum AUTHMODE is export <BASIC BEARER DIGEST NTLM NEGOTIATE ANY>;
class RC is export {
    has Str $.target;
    has Str %.hdr;
    has Hash @!hdrstack;
    has Str @!targetstack;
    has LibCurl::Easy $.curl handles <buf content error getinfo primary-ip success
            receiveheaders get-header effective-url response-code statusline version
            version-info>;
    has Readline $!readline.=new;

    method new(Str $url, |capture ) { self.bless(:$url, |capture); }
    submethod TWEAK (Str :$url, AUTHMODE :$auth, Str :$username, Str :$password,
            Str :$token, Bool :$insecure, Str :$proxy, Str :$postfields ) {

        #setup libcurl options
        my %curlopts;
        %curlopts<useragent> = 'Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101'~
                'Firefox/60.0' if !%!hdr<User-Agent>;
        %curlopts<postfields> = $postfields if ?$postfields;
        %curlopts<proxy> = $proxy if ?$proxy;

        #disable all ssl verification options if $insecure is true
        %curlopts.append: (ssl-verifyhost => 0, ssl-verifypeer => 0,
                proxy-ssl-verifyhost => 0,proxy-ssl-verifypeer=>0) if $insecure;

        #url/request target setup
        $url ~~ /(https?\:\/\/)(<-[ / ]>+)(\/.*)?/;
        %!hdr<Host> = $/[1].Str unless %!hdr<host>;
        $!target = ?$/[2] ?? $/[2].Str !! '/' unless $!target;

        $!curl.= new(URL => $/[0].Str~$/[1].Str, :path-as-is, failonerror=>0, request-target=>$!target,
                |%curlopts);
        self.set-header() if %!hdr;

        #auth setup
        if ?$auth || ?$username || ?$token {
            if ?$auth {self.set-auth($auth, :$username, :$password, :$token)}
            else { self.set-auth(:$username, :$password, :$token) }
        }

        #enable encoding handlers. setting header alone doesn't do it
        if %!hdr<Accept-Encoding> {self.setopt(accept-encoding=>%!hdr<Accept-Encoding>)}

        #push originals because why not
        @!hdrstack.push(%!hdr);
        @!targetstack.push($!target);
    }
    #Getter
    multi method target() { return $!target; }
    #Setter
    multi method target(Str $new) {
        $!target = $new; self.setopt(request-target => $!target);
        return self;
    }

    multi method get() {self.setopt(:httpget, nobody=>0); self.perform; return self;}
    multi method get(Str $temptarget, Bool :$append) {
        @!targetstack.push: self.target;
        my Str $req;
        if ?$append { $req = $!target~$temptarget; }
        else { $req = $temptarget; }
        self.setopt(request-target => $req, :httpget, nobody=>0);
        self.perform;
        self.target(@!targetstack.pop);
        return self;
    }
    #dirty. sets nobody
    multi method head() {
        self.setopt(nobody=>1, :httpget);
        self.perform;
        return self;
    }
    multi method head(Str $temptarget, Bool :$append) {
        @!targetstack.push: self.target;
        my Str $req;
        if ?$append { $req = $!target~$temptarget; }
        else { $req = $temptarget; }
        self.setopt(request-target => $req, nobody=>1, :httpget);
        self.perform;
        self.target(@!targetstack.pop);
        return self;
    }
    method options(Str $query='*', Bool :$append) {
        @!targetstack.push: self.target;
        my Str $req;
        if ?$append { $req = $!target~$query; }
        else { $req = $query; }
        self.setopt(customrequest => 'OPTIONS', request-target => $req,nobody=>0);
        self.perform;
        self.setopt(customrequest => 0);
        self.target(@!targetstack.pop);
        return self;
    }
    #`(default sends application/x-www-form-urlencoded forms. do multipart mime with
    $curl.formadd. i have not implemented this )
    proto method post(:%fields, Str :$body, Bool :$ajax, |) {
        unless %fields.defined || $body.defined {die 'You have to POST something!' }
        if %fields.defined && $body.defined {
            die 'Only one of either %fields or $body can be specified.'
        }

        if ?%fields.defined {
            if ?$ajax {
                self.setopt(postfields => hash2json(%fields), :post, nobody=>0 )
            }
            else {
                my Str $postfields;
                for %fields.keys { $postfields ~= $_~'='~%fields{$_}~'&'; }
                $postfields .= chop(1) if $postfields.ends-with('&');
                self.setopt(postfields => $postfields, :post,nobody=>0);
            }
        }
        else { self.setopt(postfields => $body) }

        if ?$ajax {
            self.hdrstack.push: %!hdr;
            %!hdr<X-Requested-With> = 'XMLHttpRequest';
            %!hdr<Content-Type> = 'application/json';
            self.set-header();
        }

        return {*};
    }
    multi method post(:%fields, Str :$body, Bool :$ajax) {
        self.perform;
        if ?$ajax {
            %!hdr = self.hdrstack.pop;
            self.set-header();
        }
        return self;
    }
    multi method post(Str $temptarget,:%fields, Str :$body, Bool :$ajax,
            Bool :$append) {
        @!targetstack.push: self.target;
        my Str $req;
        if ?$append { $req = $!target~$temptarget; }
        else { $req = $temptarget; }
        self.setopt(request-target => $req);
        self.perform;
        self.target(@!targetstack.pop);
        if ?$ajax {
            %!hdr = self.hdrstack.pop;
            self.set-header();
        }
        return self;
    }

    multi method grab-cookie(-->Str) {
        self.get();
        my $cookie = self.get-header('Set-Cookie');
        return ?$cookie ?? $cookie !! '' ;
        CATCH { say $!; say $_}
    }
    multi method grab-cookie(Str $target, :$append --> Str) {
        self.get($target, :$append);
        my $cookie = self.get-header('Set-Cookie');
        return ?$cookie ?? $cookie !! '' ;
        CATCH { say $!; say $_}
    }

    method fuzz( FUZZMODE $mode, Str $fuzzstr is copy, :$source, Bool :$ajax, :&print,
                :&mutate, :&custom) {

        my $t;
        my @s;
        my @strings;

        if ?$ajax {
            %!hdr<X-Requested-With> = 'XMLHttpRequest';
            %!hdr<Content-Type> = 'application/json';
            self.set-header();
        }

        #block that puts the current string where it's supposed to go
        my &insert-string = -> $s {
            $t = &mutate.defined ?? &mutate($s) !! $s;
            given $mode {
                when FUZZURL {
                    self.target(@s[0]~$t~@s[1]);
                    succeed;
                }
                when FUZZPOST {
                    self.setopt(postfields => (@s[0]~$t~@s[1]), :post, nobody=>0);
                    succeed;
                }
                when FUZZMIME { die 'NYI' }
                when FUZZHEADER {
                    #TODO: double check the rfc and make sure this is specified before
                    #you assume
                    my $theader = @s[0]~$t~@s[1];
                    $theader ~~ /(\w*)\:\s+(.*)/;
                    die "Couldn't parse the header" unless $/[0].defined &&
                            $/[1].defined;
                    self.setheader( $/[0] => $/[1] );
                    succeed;
                }
                default {
                    die "You shouldn't be here. Specify one of FUZZURL, FUZZPOST, "~
                        "FUZZMIME, or FUZZHEADER as the first parameter."
                }
            }
        }

        #block that makes the request and prints output
        my &doit = {
            self.perform;
            if &print.defined { &print() }
            else { say self.content; }
            if &custom.defined {
                my $tmp = &custom();
                $fuzzstr = $tmp if $tmp ~~ Str;
            }
        }

        #generate list of strings based on the wildcard in $fuzzstr
        given $fuzzstr {
            when /IFUZZ/ {
                #$fuzzstr ~~ s/IFUZZ/FUZZ/;
                while my $word = self!rl {
                    @s = $fuzzstr.split('FUZZ');
                    &insert-string($word);
                    &doit();
                }
                return self;
            }
            when /FILE/ {
                unless $source.defined && $source ~~ Str {
                    die '$source must be a path string to fuzz with a file' }
                unless $source.IO ~~ :r { die "Can't read $source." }
                #$fuzzstr ~~ s/FILE/FUZZ/;
                @strings = $source.IO.lines;
            }
            when /PROG/ {
                unless $source.defined && $source ~~ Str {
                    die '$source must contain a cmdline string to fuzz with output '~
                    'from an external program.' }
                @strings = qqx[$source].lines;
            }
            when /RANGE/ {
                unless $source.defined && $source ~~ Range {
                    die '$source must contain a perl6 Range to fuzz a range' }
                @strings = $source.list;
            }
            when /ARRAY/ {
                unless $source.defined && $source ~~ Array {
                    die '$source must contain a perl6 Array to fuzz with an array' }
                @strings = $source.Array;
            }
            default { die 'You have to fuzz something!' }
        }

        #main loop over the list of strings
        for @strings {
            @s = $fuzzstr.split(<IFUZZ FILE PROG RANGE ARRAY>,2);
            &insert-string($_);
            &doit();
        }
        return self;
    }

    method set-auth(AUTHMODE $authmode=ANY, :$token, :$username, :$password) {
        given $authmode {
            when BASIC {
                die 'need credentials' unless ?$username && ?$password;
                self.setopt(httpauth => CURLAUTH_BASIC, :$username,:$password );
                succeed;
            }
            when BEARER {
                die 'pass the token next time' unless ?$token;
                self.setopt(httpauth => CURLAUTH_BEARER, xoauth2-bearer=> $token);
                succeed;
            }
            when DIGEST {
                die 'need credentials' unless ?$username && ?$password;
                self.setopt(httpauth => CURLAUTH_DIGEST, :$username,:$password );
                succeed;
            }
            when NTLM {
                die 'need credentials' unless ?$username && ?$password;
                self.setopt(httpauth => CURLAUTH_NTLM, :$username, :$password );
                succeed;
            }
            when NEGOTIATE {
                die 'NYI';
                self.setopt(httpauth => CURLAUTH_GSSNEGOTIATE);
                succeed;
            }
            when ANY {
                self.setopt( httpauth => CURLAUTH_ANY);
                self.setopt( :$username) if ?$username;
                self.setopt( :$password) if ?$password;
                self.setopt( xoauth2-bearer=> $token) if ?$token;
                succeed;
            }
            default {
                die "Unsupported authentication method: $authmode \n"~
                    "Supported methods: 'Basic', 'Bearer', 'Digest', 'NTLM', "~
                    "'Negotiate', and 'Any'.";
            }
        }
        return self;
    }

    method !rl(Str $prompt="inject: ") {
        my $response = $!readline.readline( $prompt );
        $!readline.add-history( $response );
        return $response;
    }
    method p-statcode() {
        self.response-code.say;
    }
    method p-statline() {
        self.statline.say;
    }
    method p-etag() {
        my $tmp = self.get-header('ETag');
        if ?$tmp {$tmp.say}
        else {say 'No ETag'}
    }

    ### wrappers of wrappers ###
    #$!readline.bind-keyseq('\C-R',&relog) if &relog.defined;
    method bind-keyseq(Str $name, Str $keyseq, &func) {
        Readline::rl_add_defun($name, &func, -1);
        $!readline.bind-keyseq($keyseq,&func);
    }
    method perform(){ $!curl.perform; return self }
    method setopt(*%opts) {$!curl.setopt(|%opts); return self}
    multi method set-header(%header){
        for %header.keys { %!hdr{$_} = %header{$_} }
        self.set-header();
    }
    multi method set-header(Pair $p) {
        %!hdr{$p.key} = $p.value;
        self.set-header();
    }
    multi method set-header(){
        $!curl.clear-header;
        $!curl.set-header(|%!hdr);
        return self
    }
    multi method delete-header(Str $header) {
        %!hdr{$header}:delete;
        self.set-header();
        return self
    }
    multi method delete-header() {
        %!hdr = %();
        self.set-header();
        return self
    }
}

####################################################################################
#                         Exported subs below this point.                          #
####################################################################################

sub base64-enc($b) is export { base64-encode($b) }

#url encoding and double url encoding
sub uenc(Str $s) is export { return $s.subst(/<-alnum>/, *.ord.fmt("%%%02X"), :g);}
sub uenc2(Str $s) is export { return uenc(uenc($s)); }

sub hash2fields(%fields) is export {
    my Str $postfields;
    for %fields.keys { $postfields ~= $_~'='~%fields{$_}~'&'; }
    $postfields .= chop(1) if $postfields.ends-with('&');
    return $postfields;
}

#read json from a file and get a hash
sub file2json(Str $path) is export {
    die "Can't read file: $path" unless $path.IO ~~ :r;
    return Rakudo::Internals::JSON.from-json( $path.IO.slurp( :enc('utf8-c8') ) );
    CATCH { die "Invalid JSON, probably" }
}
sub str2json(Str $s) is export {
    return Rakudo::Internals::JSON.from-json($s);
    CATCH { die "Invalid JSON, probably" }
}
#takes hash and returns a json string
sub hash2json(%obj) is export {
    return Rakudo::Internals::JSON.to-json(%obj, :!pretty);
}

#generates a random email address
sub roll-email(Str :$dom --> Str) is export {
    my $az = 'a'..'z';
    my @tld = ['com','net','org','edu','co.uk','co','jp','us','de','fr'];
    my $d = ?$dom ?? $dom !! $az.roll((4..12).rand.Int).join~'.'~@tld.pick;
    return $az.roll((4..12).rand.Int).join~'@'~$d;
}

#`(reads a request from burp/zaproxy/whatever and returns a new object. Basic and
Bearer auth are configured automatically. Other auth schemes must be configured
manually.)
sub rc-from-file(Str $path, *%opts) is export {
    my $postfields;
    my @s = $path.IO.slurp(:enc('utf8-c8')).lines;
    #get url from start-line
    my $m = @s.shift ~~ /
        (GET || HEAD || POST || PUT || DELETE || CONNECT || OPTIONS || TRACE)
        ' '
        (<-[\s]>+)
        ' '
        (HTTP\/[\d]\.\d)
        /;
    my $url = $m[1].Str;
    die "Add the full url to your request file, including the http://..." unless
            $url.fc.starts-with('http');

    my %hdr;
    #save headers
    while @s[0] ne '' { (@s.shift.split(':',2)>>.trim) ==> %hdr; }

    #curl won't update the Content-Length header if you set it manually, so delete it
    %hdr<Content-Length>:delete;
    @s.shift; #toss the blank line before the body

    #`(everything else goes in postfields. this may or may not be technically correct.
    i'll look in the rfc one day)
    if ?@s { $postfields = @s.join("\r\n") }

    #copy & delete the Authorization header so we can set it properly later
    my $auth = %hdr<Authorization>;
    %hdr<Authorization>:delete;

    #instantiate it
    my $r;
    if $postfields { $r = RC.new($url, :%hdr, :$postfields); }
    else { $r = RC.new($url, :%hdr) }

    #set up auth if 'Authorization' header exists. only works for basic & bearer
    if ?$auth {
        $auth ~~ /'Authorization: ' (\w*) \s* (.*)/;
        my $type = $/[0];
        my $credz = $/[1];
        if $type eq 'Basic' {
            my $t = base64-decode($credz);
            my $username = $t.split(':',2).first;
            my $password = $t.split(':',2).tail;
            $r.set-auth(BASIC, :$username, :$password);
        }
        elsif $type eq 'Bearer' {
            $r.set-auth(BEARER, :token($credz) );
        }
        else { note 'Only Basic and Bearer authentication schemes are automatically '~
                    'configured from a file. You have to do this yourself.'; }
    }
    #set request type based on the startline
    given $m[0] {
        when 'GET' { $r.setopt(:httpget);succeed; }
        when 'HEAD' {$r.setopt(:httpget, :nobody);succeed; }
        when 'POST' { $r.setopt(:post); succeed; }
        default {die 'NYI'}
    }

    #forward any options to setopt
    if ?%opts { $r.setopt(|%opts) }

    return $r;
}
