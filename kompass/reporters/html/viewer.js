// kompass HTML 뷰어 (ADR-055)
// 값은 textContent·createTextNode로만 넣는다. HTML 문자열로 DOM을 만들지 않는다.
// 판정(status·severity)은 보고서에 있는 값을 표시만 한다.
(function () {
  "use strict";

  var P, R, L;
  var tabs = [];
  var currentTab = null;
  var findingsByKey = {};
  var findingsByRule = {};

  var STATUS_ORDER = ["FAIL", "ERROR", "REVIEW", "PASS", "N/A"];
  var OUTCOME_ORDER = ["FAIL", "ERROR", "REVIEW", "PASS", "N/A", "NOT_EVALUATED", "NOT_IMPLEMENTED"];
  var ACTION_OUTCOMES = ["FAIL", "ERROR", "REVIEW"];
  var SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
  var IMPORTANCE_ORDER = ["상", "중", "하"];

  // --- DOM 도우미 ---

  function el(tag, attrs) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (name) {
        var value = attrs[name];
        if (value === null || value === undefined || value === false) return;
        if (name === "class") {
          node.className = value;
        } else if (name === "href") {
          // 문서 안 주소만 허용한다
          if (String(value).charAt(0) === "#") node.setAttribute("href", value);
        } else if (name.slice(0, 2) !== "on") {
          node.setAttribute(name, value === true ? "" : String(value));
        }
      });
    }
    for (var i = 2; i < arguments.length; i++) append(node, arguments[i]);
    return node;
  }

  function append(node, child) {
    if (child === null || child === undefined || child === false) return;
    if (Array.isArray(child)) {
      child.forEach(function (c) { append(node, c); });
    } else if (typeof child === "object" && child.nodeType) {
      node.appendChild(child);
    } else {
      node.appendChild(document.createTextNode(String(child)));
    }
  }

  // null·false 자식은 건너뛴다 (replaceChildren(null)은 "null" 글자를 넣는다)
  function setChildren(node) {
    node.replaceChildren();
    for (var i = 1; i < arguments.length; i++) append(node, arguments[i]);
    return node;
  }

  // UTC ISO 시각 → "YYYY-MM-DD HH:MM:SS KST" (한국은 서머타임이 없어 고정 +9시간)
  function kst(iso) {
    var t = Date.parse(iso);
    if (isNaN(t)) return String(iso);
    return new Date(t + 9 * 3600 * 1000).toISOString().slice(0, 19).replace("T", " ") + " KST";
  }

  function on(node, event, handler) {
    node.addEventListener(event, handler);
    return node;
  }

  function cssToken(value) {
    return String(value).replace(/[^A-Za-z0-9_-]/g, "");
  }

  function statusBadge(status) {
    return el("span", { class: "badge s-" + cssToken(status) }, L.status[status] || status);
  }

  function outcomeBadge(outcome) {
    return el("span", { class: "badge s-" + cssToken(outcome) }, L.outcome[outcome] || outcome);
  }

  function table(headers, rows, emptyText) {
    if (!rows.length) return el("p", { class: "empty" }, emptyText || "결과 없음");
    return el(
      "div",
      { class: "table-wrap" },
      el(
        "table",
        null,
        el("thead", null, el("tr", null, headers.map(function (h) { return el("th", null, h); }))),
        el("tbody", null, rows)
      )
    );
  }

  function count(list, keyFn) {
    var counts = {};
    list.forEach(function (item) {
      var key = keyFn(item);
      counts[key] = (counts[key] || 0) + 1;
    });
    return counts;
  }

  function rank(order, value) {
    var i = order.indexOf(value);
    return i < 0 ? order.length : i;
  }

  function uniqueSorted(values) {
    return values
      .filter(function (v, i) { return values.indexOf(v) === i; })
      .sort();
  }

  // --- finding ---

  function findingKey(f) {
    // Python Finding.key와 같은 규칙 `룰:리전:리소스` (전역은 `-`)
    return f.rule_id + ":" + (f.region || "-") + ":" + f.resource;
  }

  function findingHref(f) {
    return "#finding=" + encodeURIComponent(findingKey(f));
  }

  function service(f) {
    return f.rule_id.split("-")[0];
  }

  function ruleLabel(ruleId) {
    return P.rules[ruleId] ? ruleId + " " + P.rules[ruleId] : ruleId;
  }

  function findingRow(f) {
    return el(
      "tr",
      null,
      el("td", null, statusBadge(f.status)),
      el("td", null, f.severity),
      el("td", null, f.rule_id),
      el("td", { class: "resource" }, el("a", { href: findingHref(f) }, f.resource)),
      el("td", null, f.region || "전역"),
      el("td", null, f.message)
    );
  }

  var FINDING_HEADERS = ["상태", "심각도", "룰", "리소스", "리전", "메시지"];

  function sortFindings(list) {
    return list.slice().sort(function (a, b) {
      return (
        rank(STATUS_ORDER, a.status) - rank(STATUS_ORDER, b.status) ||
        rank(SEVERITY_ORDER, a.severity) - rank(SEVERITY_ORDER, b.severity) ||
        (a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0)
      );
    });
  }

  function findingsOfKisa(code) {
    return R.findings.filter(function (f) {
      return f.mappings && f.mappings.kisa.indexOf(code) >= 0;
    });
  }

  // --- 상단 ---

  function renderHeader() {
    var scan = R.scan;
    var info = [
      ["점검 ID", scan.scan_id],
      ["계정", scan.account_id],
      ["리전", scan.regions.join(", ")],
      ["수행 주체", scan.caller_arn],
      ["점검 시각", P.display.started_at + " ~ " + P.display.finished_at],
      ["판정 시각", P.display.evaluated_at],
      ["보고서 생성", P.display.generated_at],
      ["kompass 버전", scan.kompass_version],
      ["매핑 해시", R.mapping_digest.slice(0, 12)]
    ];
    return el(
      "header",
      null,
      el("h1", null, "kompass 점검 결과"),
      el(
        "dl",
        { class: "info" },
        info.map(function (pair) {
          return [el("dt", null, pair[0]), el("dd", null, pair[1])];
        })
      ),
      el("p", { class: "disclaimer" }, L.notices.disclaimer)
    );
  }

  function summaryCards() {
    var outcomes = count(R.kisa_items, function (i) { return i.outcome; });
    var statuses = count(R.findings, function (f) { return f.status; });
    function cards(order, counts, badge) {
      return order
        .filter(function (k) { return counts[k]; })
        .map(function (k) {
          return el("div", { class: "card s-" + cssToken(k) }, el("strong", null, String(counts[k])), badge(k));
        });
    }
    return el(
      "section",
      { class: "summary" },
      el("h2", null, "KISA 항목 " + R.kisa_items.length + "개"),
      el("div", { class: "cards" }, cards(OUTCOME_ORDER, outcomes, function (k) { return L.outcome[k] || k; })),
      el("h2", null, "Finding " + R.findings.length + "건"),
      el("div", { class: "cards" }, cards(STATUS_ORDER, statuses, function (k) { return L.status[k] || k; }))
    );
  }

  function warnings() {
    var items = [];
    var excluded = Object.keys(R.scan.excluded_regions || {});
    if (excluded.length) {
      items.push(
        el(
          "li",
          null,
          "점검 범위에서 뺀 리전 " + excluded.length + "개 (양호가 아니라 점검 범위 밖): ",
          excluded.map(function (region) { return region + " — " + R.scan.excluded_regions[region]; }).join("; ")
        )
      );
    }
    if (R.evaluation.skipped_rules.length) {
      items.push(
        el("li", null, "스냅샷이 없어 실행하지 않은 룰 " + R.evaluation.skipped_rules.length + "개: " + R.evaluation.skipped_rules.join(", "))
      );
    }
    var errors = R.findings.filter(function (f) { return f.status === "ERROR"; }).length;
    if (errors) {
      items.push(el("li", null, L.status.ERROR + " " + errors + "건 — 수집 실패·권한 부족으로 판정하지 못함 (양호 아님)"));
    }
    return items.length ? el("section", { class: "warning" }, el("ul", null, items)) : null;
  }

  // --- 탭 ---

  function registerTab(id, title, render) {
    tabs.push({ id: id, title: title, render: render });
  }

  function showTab(id) {
    var tab = tabs.filter(function (t) { return t.id === id; })[0] || tabs[0];
    currentTab = tab.id;
    document.querySelectorAll("nav.tabs a").forEach(function (a) {
      a.setAttribute("aria-current", a.getAttribute("data-tab") === tab.id ? "page" : "false");
    });
    var panel = document.getElementById("panel");
    setChildren(panel, tab.render());
  }

  function tabNav() {
    return el(
      "nav",
      { class: "tabs" },
      tabs.map(function (t) {
        return el("a", { href: "#tab=" + t.id, "data-tab": t.id }, t.title);
      })
    );
  }

  // --- 개요 ---

  function renderOverview() {
    var items = R.kisa_items
      .filter(function (i) { return ACTION_OUTCOMES.indexOf(i.outcome) >= 0; })
      .sort(function (a, b) {
        return (
          rank(IMPORTANCE_ORDER, a.importance) - rank(IMPORTANCE_ORDER, b.importance) ||
          rank(ACTION_OUTCOMES, a.outcome) - rank(ACTION_OUTCOMES, b.outcome) ||
          (a.code < b.code ? -1 : 1)
        );
      });
    var rows = items.map(function (i) {
      return el(
        "tr",
        null,
        el("td", null, el("a", { href: "#tab=kisa" }, i.code)),
        el("td", null, i.title),
        el("td", null, i.importance),
        el("td", null, outcomeBadge(i.outcome)),
        el("td", null, countsText(i.status_counts))
      );
    });
    return el(
      "section",
      null,
      el("h2", null, "조치가 필요한 KISA 항목"),
      table(["코드", "항목", "중요도", "결과", "finding"], rows, "조치가 필요한 항목 없음"),
      overviewExtras()
    );
  }

  // 종합 위험 평가 등 개요 탭 아래쪽 (해설이 있을 때)
  function overviewExtras() {
    return null;
  }

  function countsText(counts) {
    return STATUS_ORDER.filter(function (s) { return counts[s]; })
      .map(function (s) { return (L.status[s] || s) + " " + counts[s]; })
      .join(", ");
  }

  // --- KISA 항목 ---

  function renderKisa() {
    var rows = [];
    R.kisa_items.forEach(function (item) {
      var related = sortFindings(findingsOfKisa(item.code));
      var detail = el(
        "tr",
        { class: "expand", hidden: true },
        el("td", { colspan: "7" }, table(FINDING_HEADERS, related.map(findingRow), "finding 없음"))
      );
      var toggle = el("button", { type: "button", class: "toggle", "aria-expanded": "false" }, item.code);
      on(toggle, "click", function () {
        var open = detail.hidden;
        detail.hidden = !open;
        toggle.setAttribute("aria-expanded", open ? "true" : "false");
      });
      rows.push(
        el(
          "tr",
          null,
          el("td", null, toggle),
          el("td", null, item.title),
          el("td", null, item.importance),
          el("td", null, item.automation),
          el("td", null, outcomeBadge(item.outcome)),
          el("td", null, item.rule_ids.join(", ")),
          el("td", null, countsText(item.status_counts))
        ),
        detail
      );
    });
    var unmapped = uniqueSorted(
      R.findings
        .filter(function (f) { return !f.mappings || !f.mappings.kisa.length; })
        .map(function (f) { return f.rule_id; })
    );
    return el(
      "section",
      null,
      el("h2", null, "KISA 항목별 결과"),
      el("p", { class: "hint" }, "코드를 누르면 그 항목의 finding이 펼쳐짐"),
      table(["코드", "항목", "중요도", "분류", "결과", "룰", "finding"], rows),
      el("h3", null, "KISA 대응 항목이 없는 룰"),
      unmapped.length ? el("ul", null, unmapped.map(function (r) { return el("li", null, ruleLabel(r)); })) : el("p", { class: "empty" }, "없음"),
      el("h3", null, "건너뛴 룰"),
      R.evaluation.skipped_rules.length
        ? el("ul", null, R.evaluation.skipped_rules.map(function (r) { return el("li", null, ruleLabel(r)); }))
        : el("p", { class: "empty" }, "없음")
    );
  }

  // --- Finding ---

  var filters = { status: "", severity: "", service: "", region: "", kisa: "", q: "" };

  function select(name, label, values, labelOf) {
    var node = el(
      "select",
      { "aria-label": label },
      el("option", { value: "" }, label + ": 전체"),
      values.map(function (v) {
        var option = el("option", { value: v }, labelOf ? labelOf(v) : v);
        if (filters[name] === v) option.selected = true;
        return option;
      })
    );
    return node;
  }

  function matches(f) {
    if (filters.status && f.status !== filters.status) return false;
    if (filters.severity && f.severity !== filters.severity) return false;
    if (filters.service && service(f) !== filters.service) return false;
    if (filters.region && (f.region || "전역") !== filters.region) return false;
    if (filters.kisa && !(f.mappings && f.mappings.kisa.indexOf(filters.kisa) >= 0)) return false;
    if (filters.q) {
      var q = filters.q.toLowerCase();
      if ((f.resource + "\n" + f.message).toLowerCase().indexOf(q) < 0) return false;
    }
    return true;
  }

  function renderFindings() {
    if (!R.findings.length) {
      return el("section", null, el("h2", null, "Finding"), el("p", { class: "empty" }, "결과 없음"));
    }
    var statuses = STATUS_ORDER.filter(function (s) {
      return R.findings.some(function (f) { return f.status === s; });
    });
    var severities = SEVERITY_ORDER.filter(function (s) {
      return R.findings.some(function (f) { return f.severity === s; });
    });
    var controls = [
      ["status", select("status", "상태", statuses, function (s) { return L.status[s] || s; })],
      ["severity", select("severity", "심각도", severities)],
      ["service", select("service", "서비스", uniqueSorted(R.findings.map(service)))],
      ["region", select("region", "리전", uniqueSorted(R.findings.map(function (f) { return f.region || "전역"; })))],
      [
        "kisa",
        select(
          "kisa",
          "KISA",
          uniqueSorted(
            [].concat.apply(
              [],
              R.findings.map(function (f) { return f.mappings ? f.mappings.kisa : []; })
            )
          )
        )
      ]
    ];
    var search = el("input", { type: "search", placeholder: "리소스·메시지 검색", "aria-label": "검색", value: filters.q });
    var result = el("div", null);
    var counter = el("p", { class: "hint" });

    function refresh() {
      var shown = sortFindings(R.findings.filter(matches));
      counter.textContent = R.findings.length + "건 중 " + shown.length + "건";
      setChildren(result, table(FINDING_HEADERS, shown.map(findingRow), "조건에 맞는 결과 없음"));
    }
    controls.forEach(function (pair) {
      on(pair[1], "change", function () {
        filters[pair[0]] = pair[1].value;
        refresh();
      });
    });
    on(search, "input", function () {
      filters.q = search.value;
      refresh();
    });
    refresh();
    return el(
      "section",
      null,
      el("h2", null, "Finding"),
      el("div", { class: "filters" }, controls.map(function (pair) { return pair[1]; }), search),
      counter,
      result
    );
  }

  // --- 상세 패널 ---

  function field(label, value) {
    return [el("dt", null, label), el("dd", null, value)];
  }

  function detailSections(f) {
    var m = f.mappings;
    return [
      el(
        "section",
        null,
        el("h3", null, "판정"),
        el(
          "dl",
          { class: "info" },
          field("상태", statusBadge(f.status)),
          field("심각도", f.severity),
          field("룰", ruleLabel(f.rule_id)),
          field("리소스", el("span", { class: "resource" }, f.resource)),
          field("리전", f.region || "전역"),
          field("수집 시각", kst(f.collected_at)),
          field("메시지", f.message)
        )
      ),
      el(
        "section",
        null,
        el("h3", null, "매핑"),
        m
          ? el(
              "dl",
              { class: "info" },
              field("KISA", (m.kisa.join(", ") || "없음") + (m.kisa_verified ? " (원문 근거 확인)" : " (확인 전)")),
              field("ISMS-P", (m.isms_p.join(", ") || "없음") + (m.isms_p_verified ? " (확인)" : " (초안)"))
            )
          : el("p", { class: "empty" }, "매핑 없음")
      ),
      el(
        "section",
        null,
        el("h3", null, "증적 (판정 근거 원본 설정)"),
        el("details", null, el("summary", null, "펼치기"), el("pre", null, JSON.stringify(f.evidence, null, 2)))
      )
    ];
  }

  function openFinding(key) {
    var f = findingsByKey[key];
    var aside = document.getElementById("detail");
    if (!f) {
      aside.hidden = true;
      return false;
    }
    var close = el("a", { href: "#tab=" + (currentTab || "findings"), class: "close" }, "닫기");
    setChildren(aside, 
      el("div", { class: "detail-head" }, el("h2", null, f.rule_id + " " + (P.rules[f.rule_id] || "")), close),
      detailSections(f)
    );
    aside.hidden = false;
    aside.scrollTop = 0;
    return true;
  }

  // --- 주소 해시 ---

  function route() {
    var hash = location.hash.slice(1);
    var eq = hash.indexOf("=");
    var name = eq < 0 ? hash : hash.slice(0, eq);
    var value = "";
    try {
      value = decodeURIComponent(eq < 0 ? "" : hash.slice(eq + 1));
    } catch (e) {
      value = "";
    }
    if (name === "finding" && findingsByKey[value]) {
      if (!currentTab) showTab("findings");
      openFinding(value);
      return;
    }
    document.getElementById("detail").hidden = true;
    showTab(name === "tab" ? value : "overview");
  }

  // --- 시작 ---

  function fail(app, message) {
    setChildren(app, el("p", { class: "notice" }, message));
  }

  function main() {
    var app = document.getElementById("app");
    try {
      P = JSON.parse(document.getElementById("kompass-data").textContent);
    } catch (e) {
      fail(app, "보고서 데이터를 읽지 못함");
      return;
    }
    if (!P || !P.report || P.report.format_version !== 1) {
      fail(app, "보고서 데이터를 읽지 못함 (지원하지 않는 형식)");
      return;
    }
    R = P.report;
    L = P.labels;
    R.findings.forEach(function (f) {
      findingsByKey[findingKey(f)] = f;
      (findingsByRule[f.rule_id] = findingsByRule[f.rule_id] || []).push(f);
    });
    registerTab("overview", "개요", renderOverview);
    registerTab("kisa", "KISA 항목", renderKisa);
    registerTab("findings", "Finding", renderFindings);
    setChildren(app, 
      renderHeader(),
      warnings(),
      summaryCards(),
      tabNav(),
      el("div", { class: "layout" }, el("main", { id: "panel" }), el("aside", { id: "detail", hidden: true }))
    );
    window.addEventListener("hashchange", route);
    route();
  }

  main();
})();
