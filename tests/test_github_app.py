import hashlib
import hmac

from glasswall.github_app import GitHubWebhookVerifier


def test_webhook_verifier_accepts_valid_signature() -> None:
    verifier = GitHubWebhookVerifier("super-secret")
    payload = b'{"event":"pull_request"}'
    signature = "sha256=" + hmac.new(b"super-secret", payload, hashlib.sha256).hexdigest()

    assert verifier.verify(payload, signature) is True
    assert verifier.verify(payload, "sha256=bad") is False
    assert verifier.verify(payload, None) is False
