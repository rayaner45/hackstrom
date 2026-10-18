/* HACKSTROM — loader guard.
 * Extracted from an inline <script> so the site can run under a strict
 * Content-Security-Policy without 'unsafe-inline'. */
(function () {
  "use strict";
  function hide() {
    var l = document.getElementById("loader");
    if (l) l.style.cssText = "display:none!important;";
    if (document.body) document.body.classList.remove("is-loading");
  }
  setTimeout(hide, 1200);
  setTimeout(hide, 1800);
  document.addEventListener("DOMContentLoaded", function () { setTimeout(hide, 300); });
  window.addEventListener("load", hide);
})();
