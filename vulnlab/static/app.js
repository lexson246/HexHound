/* 靶场前端脚本：故意硬编码密钥与接口路径，供信息泄露 / 接口发现验证。 */
(function () {
  // 漏洞：前端硬编码密钥（真实项目里会直接进 Git）
  var API_KEY = "AKIAIOSFODNN7EXAMPLE";
  var SIGN_SECRET = "hexhound-demo-sign-secret-0123456789";
  // 漏洞：营销活动页把可用券码写进前端（真实项目里很常见——券码被爬虫批量拿走）
  var PROMO_CODES = ["HH-RACE-100", "HH-ONCE-200"];
  var BASE = "/api";

  window.HexLab = {
    login: function (u, p) {
      return fetch(BASE + "/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: u, password: p }),
      });
    },
    user: function (uid) {
      return fetch(BASE + "/user?uid=" + uid).then(function (r) { return r.json(); });
    },
    order: function (orderId) {
      return fetch(BASE + "/order?order_id=" + orderId).then(function (r) { return r.json(); });
    },
    search: function (keyword) {
      return fetch("/api/search?q=" + encodeURIComponent(keyword) + "&page=1");
    },
    internalCallback: function (target) {
      return fetch("/fetch?url=" + encodeURIComponent(target));
    },
    wallet: function () {
      return fetch("/wallet").then(function (r) { return r.json(); });
    },
    // 营销活动页用：兑换优惠券（真实项目里这种"先查后写"最容易出竞态）
    redeem: function (code) {
      return fetch("/coupon", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "code=" + encodeURIComponent(code),
        credentials: "include",
      }).then(function (r) { return r.json(); });
    },
    // 重置密码用的一次性令牌
    resetPassword: function (user, token) {
      return fetch("/api/reset_token", {
        method: "POST",
        body: "username=" + user + "&token=" + token,
      }).then(function (r) { return r.json(); });
    },
    // 管理员导出：需要 Authorization: Bearer <jwt>（角色 role=admin）
    adminExport: function (jwt) {
      return fetch("/api/admin/export", { headers: { Authorization: "Bearer " + jwt } });
    },
    loginJwt: function (u, p) {
      return fetch("/api/jwt_login", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "username=" + u + "&password=" + p,
      }).then(function (r) { return r.json(); });
    },
    meta: { version: "1.4.2", build: "2024-11-02", keyId: "AKIAIOSFODNN7EXAMPLE" },
  };
})();
