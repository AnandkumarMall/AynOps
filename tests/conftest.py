import pytest
from unittest.mock import patch

@pytest.fixture(autouse=True)
def mock_getaddrinfo():
    with patch("tools.subdomain_takeover_tool.socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [(None, None, None, None, ("93.184.216.34", 443))]
        yield mock_gai
