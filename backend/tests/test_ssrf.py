import pytest

from app.services.ssrf import UnsafeURL, validate_outbound_url


@pytest.mark.parametrize("url", [
    "http://example.com/hook", "https://127.0.0.1/x", "https://localhost/x", "https://169.254.169.254/latest/meta-data",
    "https://10.0.0.5/x", "https://[::1]/x", "https://user:pw@example.com/x", "https://example.com:8443/x", "ftp://example.com",
    "https://service.internal/x", "https://[::ffff:127.0.0.1]/x", "https:///nohost",
])
def test_unsafe_urls_rejected(url):
    with pytest.raises(UnsafeURL):
        validate_outbound_url(url, resolve=False)


def test_public_https_literal_ip_allowed():
    assert validate_outbound_url("https://93.184.216.34/hook", resolve=False)
