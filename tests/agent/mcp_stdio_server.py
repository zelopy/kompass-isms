"""stdio 전송 확인용 MCP 서버 (tests/agent/test_mcp_server.py가 서브프로세스로 실행한다).

AWS 도구는 부르지 않으므로 자격증명 없는 가드 세션으로 만든다. 판정 결과 조회만 확인한다.
"""

import sys
from pathlib import Path

from kompass.agent.mcp_server import McpSession, build_server, serve_stdio
from kompass.agent.tools import ToolContext
from kompass.aws.guard import read_only_session
from kompass.aws.session import ScanContext
from tests.reporters.sample import ACCOUNT, DEFAULT

if __name__ == "__main__":
    scan = ScanContext(
        session=read_only_session(),
        account_id=ACCOUNT,
        partition="aws",
        caller_arn=f"arn:aws:iam::{ACCOUNT}:user/audit",
        home_region="ap-northeast-2",
        regions=("ap-northeast-2",),
        enabled_regions=("ap-northeast-2",),
    )
    print("stdio 서버 시작", file=sys.stderr)
    serve_stdio(build_server(McpSession(DEFAULT, ToolContext(scan), Path(sys.argv[1]))))
