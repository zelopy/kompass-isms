// kompass HTML 뷰어. 값은 textContent로만 넣는다 (ADR-055)
(function () {
  "use strict";

  function fail(app, message) {
    var p = document.createElement("p");
    p.className = "notice";
    p.textContent = message;
    app.replaceChildren(p);
  }

  function main() {
    var app = document.getElementById("app");
    var payload;
    try {
      payload = JSON.parse(document.getElementById("kompass-data").textContent);
    } catch (e) {
      fail(app, "보고서 데이터를 읽지 못함");
      return;
    }
    if (!payload || !payload.report || payload.report.format_version !== 1) {
      fail(app, "보고서 데이터를 읽지 못함 (지원하지 않는 형식)");
      return;
    }
    var h1 = document.createElement("h1");
    h1.textContent = "점검 " + payload.report.scan.scan_id;
    app.replaceChildren(h1);
  }

  main();
})();
