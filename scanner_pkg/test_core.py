from core import NetworkScanner

def test_scan_single_returns_dict():
    scanner = NetworkScanner()
    result = scanner.scan_single('127.0.0.1')
    assert isinstance(result, dict)
    assert 'ip' in result

def test_scan_single_has_expected_keys():
    scanner = NetworkScanner()
    result = scanner.scan_single('127.0.0.1')
    expected_keys = {'ip', 'os', 'scan_duration', 'open_ports', 'message'}
    assert expected_keys.issubset(result.keys()) or 'error' in result

def test_invalid_ip_handled_gracefully():
    scanner = NetworkScanner()
    result = scanner.scan_single('999.999.999.999')
    assert 'error' in result

if __name__ == "__main__":
    test_scan_single_returns_dict()
    print("Test 1 passed")
    test_scan_single_has_expected_keys()
    print("Test 2 passed")
    test_invalid_ip_handled_gracefully()
    print("Test 3 passed")
    print("All tests passed")
