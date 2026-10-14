"""S3-006 버킷 ACL에 의한 전체 공개 (KISA CA-10, docs/RULES.md).

객체 소유권이 `BucketOwnerEnforced`(ACL 비활성화)면 PASS. 그 외에는 ACL에 `AllUsers`·
`AuthenticatedUsers` 대상 권한이 있으면 FAIL이며, 막고 있는 `IgnorePublicAcls` 값을 evidence에
남긴다 (공통 원칙 "설정이 존재하면 FAIL").
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.s3._buckets import MISSING, BucketRule, account_block, block_value

_PUBLIC_GRANTEES = frozenset(
    {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
)
_ACL_DISABLED = "BucketOwnerEnforced"


def _object_ownership(controls: Any) -> str | None:
    if not isinstance(controls, dict):
        return None
    rules = controls.get("Rules", [])
    return rules[0].get("ObjectOwnership") if rules else None


class S3006PublicBucketAcl(BucketRule):
    id: ClassVar[str] = "S3-006"
    title: ClassVar[str] = "버킷 ACL에 의한 전체 공개"
    severity: ClassVar[Severity] = Severity.HIGH

    def judge(
        self,
        snapshot: Snapshot,
        settings: Settings,
        name: str,
        region: str | None,
        details: dict[str, Any],
    ) -> Finding:
        ownership = _object_ownership(details.get("ownership_controls"))
        evidence: dict[str, Any] = {"object_ownership": ownership}
        if ownership == _ACL_DISABLED:
            return self.bucket_finding(
                snapshot, name, region, Status.PASS, f"ACL이 비활성화되어 있음: {name}", evidence
            )
        acl = details.get("acl", MISSING)
        if acl is MISSING:
            return self.bucket_error(snapshot, name, region, "s3:GetBucketAcl", "버킷 ACL")
        public_grants = [
            {"grantee": grant["Grantee"]["URI"], "permission": grant.get("Permission")}
            for grant in acl.get("Grants", [])
            if grant.get("Grantee", {}).get("URI") in _PUBLIC_GRANTEES
        ]
        evidence["public_grants"] = public_grants
        if public_grants:
            evidence["ignore_public_acls"] = {
                "bucket": block_value(details.get("public_access_block"), "IgnorePublicAcls"),
                "account": block_value(account_block(snapshot), "IgnorePublicAcls"),
            }
            status, message = Status.FAIL, f"ACL이 모든 사용자에게 권한을 부여함: {name}"
        else:
            status, message = Status.PASS, f"ACL에 전체 공개 권한이 없음: {name}"
        return self.bucket_finding(snapshot, name, region, status, message, evidence)
