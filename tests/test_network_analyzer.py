
from scanners.network.network_analyzer import NetworkSecurityAnalyzer


def test_network_security_analysis():
    nmap_result = {
        "target": "127.0.0.1",
        "ip": "127.0.0.1",
        "host_status": "UP",
        "ports": [
            {"port": "22", "protocol": "tcp", "state": "open", "service": "ssh"},
            {"port": "23", "protocol": "tcp", "state": "open", "service": "telnet"},
            {"port": "80", "protocol": "tcp", "state": "open", "service": "http"},
            {"port": "3306", "protocol": "tcp", "state": "open", "service": "mysql"},
            {"port": "443", "protocol": "tcp", "state": "open", "service": "https"},
        ],
    }

    findings = NetworkSecurityAnalyzer().analyze(nmap_result)

    # Five individual port findings plus two correlation findings.
    assert len(findings) == 7
    assert any(f["finding_id"] == "NETWORK-SENSITIVE-EXPOSURE" for f in findings)
    assert any(f["finding_id"] == "NETWORK-EXPOSURE" for f in findings)


def test_closed_port_is_ignored():
    result = {
        "target": "127.0.0.1",
        "ports": [{"port": "22", "protocol": "tcp", "state": "closed", "service": "ssh"}],
    }

    assert NetworkSecurityAnalyzer().analyze(result) == []


def test_service_version_exposure():
    result = {
        "target": "127.0.0.1",
        "ports": [{
            "port": "80", "protocol": "tcp", "state": "open",
            "service": "http", "version": None
        }],
    }

    findings = NetworkSecurityAnalyzer().analyze(result)
    assert len(findings) == 1
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["title"] == "Unencrypted HTTP service exposed"


def test_version_exposure_does_not_override_higher_severity():
    result = {
        "target": "127.0.0.1",
        "ports": [{
            "port": "3306", "protocol": "tcp", "state": "open",
            "service": "mysql", "version": "8.0"
        }],
    }

    findings = NetworkSecurityAnalyzer().analyze(result)
    assert len(findings) == 1
    assert findings[0]["severity"] == "High"
    assert findings[0]["title"] == "Database service exposed: mysql"


def test_no_version_keeps_basic_finding():
    result = {
        "target": "127.0.0.1",
        "ports": [{
            "port": "443", "protocol": "tcp", "state": "open",
            "service": "https", "version": None
        }],
    }

    findings = NetworkSecurityAnalyzer().analyze(result)
    assert len(findings) == 1
    assert findings[0]["severity"] == "Info"
    assert findings[0]["title"] == "Open port detected :443"


def test_smb_service_exposure():
    result = {
        "target": "127.0.0.1",
        "ports": [{
            "port": "445", "protocol": "tcp", "state": "open", "service": "smb"
        }],
    }

    findings = NetworkSecurityAnalyzer().analyze(result)
    assert len(findings) == 1
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["title"] == "SMB service exposed"


def test_smb_version_does_not_override_medium_severity():
    result = {
        "target": "127.0.0.1",
        "ports": [{
            "port": "445", "protocol": "tcp", "state": "open",
            "service": "smb", "version": "Samba 4"
        }],
    }

    findings = NetworkSecurityAnalyzer().analyze(result)
    assert len(findings) == 1
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["title"] == "SMB service exposed"


def test_ftp_version_does_not_override_medium_severity():
    result = {
        "target": "127.0.0.1",
        "ports": [{
            "port": "21", "protocol": "tcp", "state": "open",
            "service": "ftp", "version": "vsftpd 3.0.3"
        }],
    }

    findings = NetworkSecurityAnalyzer().analyze(result)
    assert len(findings) == 1
    assert findings[0]["finding_id"] == "NETWORK-21"
    assert findings[0]["scanner"] == "NetworkSecurity"
    assert findings[0]["target"] == "127.0.0.1"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["title"] == "Insecure file transfer service exposed: ftp"


def test_udp_service_exposure():
    result = {
        "target": "127.0.0.1",
        "ports": [{
            "port": "53", "protocol": "udp", "state": "open", "service": "domain"
        }],
    }

    findings = NetworkSecurityAnalyzer().analyze(result)
    assert len(findings) == 1
    assert findings[0]["finding_id"] == "NETWORK-53"
    assert findings[0]["scanner"] == "NetworkSecurity"
    assert findings[0]["target"] == "127.0.0.1"
    assert findings[0]["severity"] == "Info"
    assert findings[0]["title"] == "Open port detected :53"


def test_multiple_open_ports_increase_exposure_surface():
    result = {
        "target": "127.0.0.1",
        "ports": [
            {"port": str(p), "protocol": "tcp", "state": "open", "service": "unknown"}
            for p in [80, 81, 82, 83]
        ],
    }

    findings = NetworkSecurityAnalyzer().analyze(result)
    assert len(findings) == 5
    assert any(f["finding_id"] == "NETWORK-EXPOSURE" for f in findings)


def test_three_or_fewer_open_ports_do_not_create_exposure_finding():
    result = {
        "target": "127.0.0.1",
        "ports": [
            {"port": str(p), "protocol": "tcp", "state": "open", "service": "unknown"}
            for p in [80, 81, 82]
        ],
    }

    findings = NetworkSecurityAnalyzer().analyze(result)
    assert len(findings) == 3
    assert not any(f["finding_id"] == "NETWORK-EXPOSURE" for f in findings)


def test_host_down_detection():
    result = {
        "target": "192.0.2.1",
        "host_status": "DOWN",
        "ports": [],
    }

    findings = NetworkSecurityAnalyzer().analyze(result)
    assert len(findings) == 1
    assert findings[0]["finding_id"] == "NETWORK-HOST-DOWN"
    assert findings[0]["severity"] == "Info"


def test_unknown_service_is_handled_safely():
    result = {
        "target": "127.0.0.1",
        "ports": [{
            "port": "9999", "protocol": "tcp", "state": "open", "service": "unknown"
        }],
    }

    findings = NetworkSecurityAnalyzer().analyze(result)
    assert len(findings) == 1
    assert findings[0]["finding_id"] == "NETWORK-9999"
    assert findings[0]["scanner"] == "NetworkSecurity"
    assert findings[0]["target"] == "127.0.0.1"
    assert findings[0]["severity"] == "Info"
    assert findings[0]["title"] == "Open port detected :9999"


def test_multiple_sensitive_services_are_detected():
    result = {
        "target": "192.168.1.10",
        "ip": "192.168.1.10",
        "host_status": "UP",
        "ports": [
            {"port": "23", "protocol": "tcp", "state": "open", "service": "telnet"},
            {"port": "3306", "protocol": "tcp", "state": "open", "service": "mysql"},
        ],
    }

    findings = NetworkSecurityAnalyzer().analyze(result)

    # Two individual findings plus the correlation finding.
    assert len(findings) == 3
    assert any(f["finding_id"] == "NETWORK-23" for f in findings)
    assert any(f["finding_id"] == "NETWORK-3306" for f in findings)
    assert any(f["finding_id"] == "NETWORK-SENSITIVE-EXPOSURE" for f in findings)


def test_sensitive_services_exposure_correlation():
    result = {
        "target": "192.168.1.10",
        "ports": [
            {"port": "23", "protocol": "tcp", "state": "open", "service": "telnet"},
            {"port": "3306", "protocol": "tcp", "state": "open", "service": "mysql"},
        ],
    }

    findings = NetworkSecurityAnalyzer().analyze(result)
    correlation = next(
        f for f in findings
        if f["finding_id"] == "NETWORK-SENSITIVE-EXPOSURE"
    )

    assert correlation["severity"] == "High"
    assert "mysql" in correlation["evidence"]
    assert "telnet" in correlation["evidence"]
