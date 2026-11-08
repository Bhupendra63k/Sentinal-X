from scanners.reconnaissance.nmap.parser import NmapParser


def test_parse_target_and_ip():
    parser = NmapParser()

    output = """Nmap scan report for localhost (127.0.0.1)
Host is up (0.0010s latency).
"""

    result = parser.parse(output)

    assert result["target"] == "localhost"
    assert result["ip"] == "127.0.0.1"


def test_parse_host_status():
    parser = NmapParser()

    output = """Nmap scan report for localhost (127.0.0.1)
Host is up (0.0010s latency).
"""

    result = parser.parse(output)

    assert result["host_status"] == "UP"


def test_parse_single_port():
    parser = NmapParser()

    output = """Nmap scan report for localhost (127.0.0.1)
Host is up.
PORT     STATE SERVICE
22/tcp   open  ssh
"""

    result = parser.parse(output)

    assert len(result["ports"]) == 1

    assert result["ports"][0] == {
        "port": "22",
        "protocol": "tcp",
        "state": "open",
        "service": "ssh",
        "version": None
    }


def test_parse_service_version():
    parser = NmapParser()

    output = """Nmap scan report for localhost (127.0.0.1)
Host is up.
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1
"""

    result = parser.parse(output)

    assert len(result["ports"]) == 1

    port = result["ports"][0]

    assert port["port"] == "22"
    assert port["protocol"] == "tcp"
    assert port["state"] == "open"
    assert port["service"] == "ssh"
    assert port["version"] == "OpenSSH 9.2p1"


def test_parse_multiple_ports():
    parser = NmapParser()

    output = """Nmap scan report for localhost (127.0.0.1)
Host is up.
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1
80/tcp   open  http    Apache httpd 2.4.57
443/tcp  open  https   nginx 1.24.0
"""

    result = parser.parse(output)

    assert len(result["ports"]) == 3

    assert result["ports"][0]["port"] == "22"
    assert result["ports"][0]["service"] == "ssh"
    assert result["ports"][0]["version"] == "OpenSSH 9.2p1"

    assert result["ports"][1]["port"] == "80"
    assert result["ports"][1]["service"] == "http"
    assert result["ports"][1]["version"] == "Apache httpd 2.4.57"

    assert result["ports"][2]["port"] == "443"
    assert result["ports"][2]["service"] == "https"
    assert result["ports"][2]["version"] == "nginx 1.24.0"


def test_parse_port_protocol_and_state():
    parser = NmapParser()

    output = """Nmap scan report for localhost (127.0.0.1)
Host is up.
53/udp open domain
"""

    result = parser.parse(output)

    port = result["ports"][0]

    assert port["port"] == "53"
    assert port["protocol"] == "udp"
    assert port["state"] == "open"
    assert port["service"] == "domain"
    assert port["version"] is None


def test_parse_version_with_multiple_words():
    parser = NmapParser()

    output = """Nmap scan report for localhost (127.0.0.1)
Host is up.
80/tcp open http Apache httpd 2.4.57 Ubuntu
"""

    result = parser.parse(output)

    port = result["ports"][0]

    assert port["service"] == "http"
    assert port["version"] == "Apache httpd 2.4.57 Ubuntu"


def test_no_ports_returns_empty_list():
    parser = NmapParser()

    output = """Nmap scan report for localhost (127.0.0.1)
Host is up.
"""

    result = parser.parse(output)

    assert result["ports"] == []


def test_empty_output_returns_default_structure():
    parser = NmapParser()

    result = parser.parse("")

    assert result == {
        "target": None,
        "ip": None,
        "host_status": None,
        "ports": [],
        "scanner": None,
        "scan_type": None
    }


def test_unrelated_lines_are_ignored():
    parser = NmapParser()

    output = """Starting Nmap
Nmap scan report for localhost (127.0.0.1)
Host is up.
Some unrelated information
22/tcp open ssh OpenSSH 9.2p1
Another unrelated line
"""

    result = parser.parse(output)

    assert result["target"] == "localhost"
    assert result["ip"] == "127.0.0.1"
    assert result["host_status"] == "UP"

    assert len(result["ports"]) == 1

    port = result["ports"][0]

    assert port["port"] == "22"
    assert port["protocol"] == "tcp"
    assert port["state"] == "open"
    assert port["service"] == "ssh"
    assert port["version"] == "OpenSSH 9.2p1"