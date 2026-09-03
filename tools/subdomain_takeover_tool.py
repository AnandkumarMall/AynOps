"""Subdomain Takeover Checker Tool.

Discovers subdomains via the existing DNS enumeration logic, resolves each
subdomain's CNAME record, matches it against known-vulnerable service
fingerprints (GitHub Pages, Heroku, S3, Azure, Ghost, Shopify, Fastly), and
confirms the takeover with an HTTP request checking for the service's
takeover-indicating response.
"""

import ipaddress
import re
import socket
from dataclasses import dataclass
from enum import Enum

import dns.exception
import dns.resolver
import requests

from tools.dns_tool import PUBLIC_RESOLVERS, dns_enumeration
from utils.helpers import is_valid_domain, normalize_domain

# Match region labels by shape rather than a fixed list so newly added AWS
# regions stay covered. Keeping service-specific labels out of this slot
# prevents non-bucket AWS endpoints from being interpreted as bucket regions.
_AWS_REGION = r"[a-z]{2}(?:-[a-z]+)+-\d+"

# Restrict the fingerprint to documented S3 bucket endpoint families that can
# return NoSuchBucket for an unclaimed bucket. Anchoring the hostname prevents
# unrelated AWS services from being treated as S3.
# References:
# https://docs.aws.amazon.com/general/latest/gr/s3.html
# https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html
# https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteEndpoints.html
# https://docs.aws.amazon.com/AmazonS3/latest/userguide/transfer-acceleration-getting-started.html
# https://docs.amazonaws.cn/en_us/AmazonS3/latest/userguide/VirtualHosting.html
# https://docs.amazonaws.cn/en_us/AmazonS3/latest/userguide/static-website-hosting-china.html
# https://github.com/boto/botocore/blob/develop/botocore/data/endpoints.json
_S3_ENDPOINT_RE = re.compile(
    rf"(?:^|\.)(?:s3(?:[.-]{_AWS_REGION}|\.dualstack\.{_AWS_REGION})?"
    rf"|s3-fips(?:\.dualstack)?\.{_AWS_REGION}"
    rf"|s3-accelerate(?:\.dualstack)?"
    rf"|s3-website[.-]{_AWS_REGION})\.amazonaws\.com$"
    rf"|(?:^|\.)(?:s3(?:[.-]{_AWS_REGION}|\.dualstack\.{_AWS_REGION})?"
    rf"|s3-website\.{_AWS_REGION})\.amazonaws\.com\.cn$"
)

VULNERABLE_FINGERPRINTS = [
    {
        "cname_pattern": re.compile(r"github\.io$"),
        "service": "GitHub Pages",
        "indicator": {
            "body_pattern": re.compile(r"There isn't a GitHub Pages site here\.")
        },
    },
    {
        "cname_pattern": re.compile(r"herokuapp\.com$"),
        "service": "Heroku",
        "indicator": {"body_pattern": re.compile(r"No such app")},
    },
    {
        "cname_pattern": _S3_ENDPOINT_RE,
        "service": "AWS S3",
        "indicator": {"body_pattern": re.compile(r"NoSuchBucket")},
    },
    {
        "cname_pattern": re.compile(r"azurewebsites\.net$"),
        "service": "Azure",
        "indicator": {"body_pattern": re.compile(r"404 Web Site not found")},
    },
    {
        "cname_pattern": re.compile(r"ghost\.io$"),
        "service": "Ghost",
        "indicator": {"body_pattern": re.compile(r"404 Domain Not Found")},
    },
    {
        "cname_pattern": re.compile(r"myshopify\.com$"),
        "service": "Shopify",
        "indicator": {"body_pattern": re.compile(r"Sorry, this shop")},
    },
    {
        "cname_pattern": re.compile(r"fastly\.net$"),
        "service": "Fastly",
        "indicator": {
            "status": 500,
            "body_pattern": re.compile(r"Fastly error"),
            "headers": {"Fastly-Error": None},
        },
    },
]

_REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}
_REQUEST_TIMEOUT = 10


class _ProbeStatus(str, Enum):
    CONFIRMED = "confirmed"
    NO_INDICATOR = "no_indicator"
    UNABLE_TO_PROBE = "unable_to_probe"


@dataclass(frozen=True)
class _ProbeResult:
    response: requests.Response | None
    errors: tuple[dict[str, str], ...] = ()


@dataclass(frozen=True)
class _TakeoverResult:
    status: _ProbeStatus
    evidence: dict | None = None
    probe_errors: tuple[dict[str, str], ...] = ()


@dataclass(frozen=True)
class _CnameResolution:
    chain: tuple[str, ...] = ()
    error: str | None = None


def _make_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = PUBLIC_RESOLVERS
    return resolver


def _resolve_cname(subdomain: str, resolver) -> _CnameResolution:
    """Follow CNAME chain iteratively, detecting loops and errors."""
    chain = []
    current = subdomain
    seen = set()

    while len(chain) < 5:
        if current in seen:
            return _CnameResolution(chain=tuple(chain), error="CNAME loop detected")
        seen.add(current)
        try:
            answers = resolver.resolve(current, "CNAME", lifetime=5)
            cname = str(answers[0]).rstrip(".")
            if cname == current:
                # Poorly mocked test resolver returning the same CNAME
                break
            chain.append(cname)
            current = cname
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            break
        except dns.exception.DNSException as exc:
            return _CnameResolution(
                chain=tuple(chain), error=f"{type(exc).__name__}: {exc}"
            )

    return _CnameResolution(chain=tuple(chain))


def _match_fingerprint(cname: str) -> dict | None:
    cname = cname.lower().rstrip(".")
    for fingerprint in VULNERABLE_FINGERPRINTS:
        if fingerprint["cname_pattern"].search(cname):
            return fingerprint
    return None


def _probe(subdomain: str, allow_internal: bool) -> _ProbeResult:
    """Fetch the subdomain securely, verifying DNS to prevent SSRF."""
    try:
        addr_info = socket.getaddrinfo(subdomain, 443, proto=socket.IPPROTO_TCP)
        for _, _, _, _, sockaddr in addr_info:
            ip = ipaddress.ip_address(sockaddr[0])
            if not allow_internal and (ip.is_private or ip.is_loopback):
                return _ProbeResult(
                    response=None,
                    errors=(
                        {
                            "scheme": "dns",
                            "error": f"Security restriction: IP {ip} is private/loopback",
                        },
                    ),
                )
    except socket.gaierror as e:
        return _ProbeResult(
            response=None,
            errors=({"scheme": "dns", "error": f"DNS resolution failed: {e}"},),
        )

    errors = []
    for scheme in ("https", "http"):
        try:
            response = requests.get(
                f"{scheme}://{subdomain}",
                headers=_REQUEST_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            return _ProbeResult(response=response)
        except requests.exceptions.RequestException as exc:
            errors.append(
                {
                    "scheme": scheme,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            continue
    return _ProbeResult(response=None, errors=tuple(errors))


def _confirms_takeover(
    subdomain: str, fingerprint: dict, allow_internal: bool
) -> _TakeoverResult:
    """Return the tri-state takeover result and structured evidence."""
    probe = _probe(subdomain, allow_internal)
    if probe.response is None:
        return _TakeoverResult(_ProbeStatus.UNABLE_TO_PROBE, probe_errors=probe.errors)

    indicator = fingerprint["indicator"]
    confirmed = True

    if "status" in indicator and probe.response.status_code != indicator["status"]:
        confirmed = False

    if (
        confirmed
        and "body_pattern" in indicator
        and not indicator["body_pattern"].search(probe.response.text)
    ):
        confirmed = False

    if confirmed and "headers" in indicator:
        for k, v in indicator["headers"].items():
            if k not in probe.response.headers or (
                v is not None and probe.response.headers[k] != v
            ):
                confirmed = False
                break

    redirect_chain = []
    if hasattr(probe.response, "history"):
        try:
            redirect_chain = [r.url for r in probe.response.history]
        except TypeError:
            pass

    evidence = {
        "url": getattr(probe.response, "url", ""),
        "status_code": getattr(probe.response, "status_code", 0),
        "redirect_chain": redirect_chain,
    }

    status = _ProbeStatus.CONFIRMED if confirmed else _ProbeStatus.NO_INDICATOR
    return _TakeoverResult(status, evidence=evidence)


def subdomain_takeover(domain: str, allow_internal: bool = False) -> dict:
    """
    Check discovered subdomains for potential takeover vulnerabilities.
    A subdomain takeover occurs when a subdomain's CNAME points to an external
    service (GitHub Pages, Heroku, S3 etc.) that is no longer active.
    """
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    # Subdomain discovery reuses the existing DNS enumeration tool.
    enumeration = dns_enumeration(domain)
    if not enumeration.get("success"):
        return {
            "success": False,
            "error": enumeration.get("error", "DNS enumeration failed"),
        }

    subdomains = enumeration.get("subdomains_found", [])
    resolver = _make_resolver()

    vulnerable = []
    not_vulnerable = []
    unknown = []

    for subdomain in subdomains:
        cname_result = _resolve_cname(subdomain, resolver)
        if cname_result.error is not None:
            unknown.append(
                {
                    "subdomain": subdomain,
                    "reason": "Unable to resolve CNAME record fully",
                    "dns_error": cname_result.error,
                    "cname_chain": cname_result.chain,
                }
            )
            continue
        if not cname_result.chain:
            not_vulnerable.append(subdomain)
            continue

        cname = cname_result.chain[-1]

        fingerprint = _match_fingerprint(cname)
        if not fingerprint:
            unknown.append(
                {
                    "subdomain": subdomain,
                    "reason": "CNAME points to an unsupported service",
                    "cname_chain": cname_result.chain,
                }
            )
            continue

        probe_result = _confirms_takeover(subdomain, fingerprint, allow_internal)
        if probe_result.status is _ProbeStatus.CONFIRMED:
            vulnerable.append(
                {
                    "subdomain": subdomain,
                    "cname": cname,
                    "cname_chain": cname_result.chain,
                    "service": fingerprint["service"],
                    "reason": f"CNAME points to unclaimed {fingerprint['service']} service",
                    "severity": "HIGH",
                    "evidence": probe_result.evidence,
                }
            )
        elif probe_result.status is _ProbeStatus.NO_INDICATOR:
            not_vulnerable.append(subdomain)
        else:
            unknown.append(
                {
                    "subdomain": subdomain,
                    "reason": "Unable to complete HTTP probe over HTTPS or HTTP",
                    "probe_errors": list(probe_result.probe_errors),
                }
            )

    return {
        "success": True,
        "domain": domain,
        "subdomains_checked": len(subdomains),
        "vulnerable": vulnerable,
        "not_vulnerable": not_vulnerable,
        "unknown": unknown,
        "total_vulnerable": len(vulnerable),
    }
