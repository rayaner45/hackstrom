  (function(){
    "use strict";

    /* ==================== AUTH GATE (client-side, 2nd layer) ==================== */
    // The REAL gate is enforced on the server (Cloudflare Worker): the admin HTML is
    // only sent to clients holding a valid signed session cookie. This client-side
    // check is a fallback for copies of the page served outside the Worker.
    // PBKDF2-SHA256 (random salt + 200k iterations). See ADMIN.md to rotate it.
    var PASS_SALT = "a69a645ca297e6a4b1e41657b575a34c";
    var PASS_ITER = 200000;
    var PASS_KEY  = "e187d54d366eaaa92a1b18f9549c5be3dd82873549fc8c2502266fda82eb63db";
    var MAX_ATTEMPTS = 5;
    var LOCKOUT_TIME = 30000; // 30 seconds

    // Trust the server session: the Worker injects this marker into the served page.
    var SERVER_AUTH = !!document.querySelector('meta[name="hs-server-auth"]');

    var loginOverlay = document.getElementById("loginOverlay");
    var loginForm = document.getElementById("loginForm");
    var loginPass = document.getElementById("loginPass");
    var loginError = document.getElementById("loginError");
    var loginBtn = document.getElementById("loginBtn");
    var adminContent = document.getElementById("adminContent");

    // Check if already authenticated (server session OR local fallback)
    var session = null;
    try{ session = sessionStorage.getItem("hs_admin_auth"); }catch(e){}
    if(SERVER_AUTH || session === "ok"){
      loginOverlay.classList.add("hide");
      adminContent.style.display = "";
    }

    // PBKDF2-SHA256 key derivation (strong; no insecure fallback)
    function deriveKey(password){
      var enc = new TextEncoder();
      if(!(window.crypto && window.crypto.subtle)){
        return Promise.reject(new Error("WebCrypto unavailable"));
      }
      return window.crypto.subtle
        .importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"])
        .then(function(key){
          return window.crypto.subtle.deriveBits(
            { name: "PBKDF2", salt: enc.encode(PASS_SALT), iterations: PASS_ITER, hash: "SHA-256" },
            key, 256
          );
        })
        .then(function(buf){
          return Array.from(new Uint8Array(buf)).map(function(b){ return b.toString(16).padStart(2,"0"); }).join("");
        });
    }

    // Rate limiting
    var attempts = 0;
    var lockedUntil = 0;

    function getAttempts(){
      try{ return parseInt(localStorage.getItem("hs_login_attempts") || "0", 10); }catch(e){ return 0; }
    }
    function setAttempts(n){
      try{ localStorage.setItem("hs_login_attempts", String(n)); }catch(e){}
    }
    function getLockout(){
      try{ return parseInt(localStorage.getItem("hs_login_lockout") || "0", 10); }catch(e){ return 0; }
    }
    function setLockout(t){
      try{ localStorage.setItem("hs_login_lockout", String(t)); }catch(e){}
    }

    function showError(msg){
      if(loginError) loginError.textContent = msg;
    }

    function lockLogin(seconds){
      var end = Date.now() + seconds * 1000;
      setLockout(end);
      var remaining = seconds;
      if(loginBtn) loginBtn.disabled = true;
      var timer = setInterval(function(){
        remaining--;
        if(remaining <= 0){
          clearInterval(timer);
          setAttempts(0);
          setLockout(0);
          if(loginBtn) loginBtn.disabled = false;
          showError("");
        } else {
          showError("🔒 مغلق " + remaining + " ثانية");
        }
      }, 1000);
    }

    // Login handler
    if(loginForm){
      loginForm.addEventListener("submit", function(e){
        e.preventDefault();
        var pass = loginPass ? loginPass.value : "";
        if(!pass){ showError("⚠️ أدخل كلمة المرور"); return; }

        // Check lockout
        var lockEnd = getLockout();
        if(Date.now() < lockEnd){
          var secs = Math.ceil((lockEnd - Date.now()) / 1000);
          showError("🔒 مغلق " + secs + " ثانية");
          return;
        }

        // Check attempts
        attempts = getAttempts();
        if(attempts >= MAX_ATTEMPTS){
          lockLogin(LOCKOUT_TIME / 1000);
          return;
        }

        // Verify password
        deriveKey(pass).then(function(hash){
          if(hash === PASS_KEY){
            // SUCCESS
            try{ sessionStorage.setItem("hs_admin_auth", "ok"); }catch(e){}
            setAttempts(0);
            loginOverlay.classList.add("hide");
            adminContent.style.display = "";
          } else {
            // FAIL
            attempts++;
            setAttempts(attempts);
            var remaining = MAX_ATTEMPTS - attempts;
            if(remaining <= 0){
              showError("🔒 تجاوزت المحاولات — انتظر 30 ثانية");
              lockLogin(LOCKOUT_TIME / 1000);
            } else {
              showError("❌ كلمة مرور خاطئة — متبقي " + remaining + " محاولات");
              if(loginPass) loginPass.value = "";
              if(loginPass) loginPass.focus();
            }
          }
        }).catch(function(){ showError("⚠️ المتصفح لا يدعم الحماية المطلوبة"); });
      });
    }

    // If not logged in, keep admin hidden but still initialize below
    // The login overlay covers everything visually until authenticated
    if(!session || session !== "ok"){
      // Admin content stays hidden via display:none in HTML
      // Login overlay is position:fixed and covers the page
    }

    var KEY = "hs_leaderboard_v2";
    var players = [];
    var editingIndex = -1;

    function $(id){ return document.getElementById(id); }

    function esc(s){
      var d = document.createElement("div");
      d.textContent = String(s);
      return d.innerHTML;
    }

    // Escape a value for safe use inside an HTML attribute (quoted)
    function escAttr(s){
      return String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
    }

    function toast(msg){
      var t = $("toast");
      if(!t) return;
      t.textContent = msg;
      t.className = "toast show";
      clearTimeout(t._tid);
      t._tid = setTimeout(function(){ t.className = "toast"; }, 2500);
    }

    /* ---- SAVE / LOAD ---- */
    function save(){
      try{ localStorage.setItem(KEY, JSON.stringify(players)); }catch(e){}
    }

    function load(){
      try{
        var raw = localStorage.getItem(KEY);
        if(raw){
          var arr = JSON.parse(raw);
          if(Array.isArray(arr)){ players = arr; return true; }
        }
      }catch(e){}
      return false;
    }

    /* ---- RENDER ---- */
    function render(){
      players.sort(function(a,b){ return (b.points||0) - (a.points||0); });
      players.forEach(function(p,i){ p.rank = i+1; });
      save();

      var tbody = $("tbody");
      if(!tbody) return;

      if(players.length === 0){
        tbody.innerHTML = '<tr><td colspan="5" class="empty"><i class="bi bi-inbox"></i>لا يوجد لاعبون — أضف أول لاعب من النموذج بالأعلى</td></tr>';
      } else {
        var html = "";
        for(var i = 0; i < players.length; i++){
          var p = players[i];
          var rc = p.rank <= 3 ? " t-rank--" + p.rank : "";
          var av = "";
          if(p.avatar){
            av = '<img class="t-avatar" src="' + escAttr(p.avatar) + '" alt="" style="width:1.7rem;height:1.7rem;border-radius:50%;object-fit:cover;margin-inline-end:.5rem;vertical-align:middle">';
          }
          html += '<tr' + (i === editingIndex ? ' class="editing"' : '') + '>'
            + '<td><span class="t-rank' + rc + '">#' + Number(p.rank) + '</span></td>'
            + '<td>' + av + '<strong>' + esc(p.name || "?") + '</strong></td>'
            + '<td><span class="t-pts">' + Number(p.points || 0).toLocaleString() + '</span></td>'
            + '<td style="font-size:1.2rem">' + esc(p.badge || "—") + '</td>'
            + '<td><div class="t-actions">'
            + '<button type="button" class="icon-btn icon-btn--up" data-act="up" data-i="' + i + '" title="لأعلى"><i class="bi bi-arrow-up"></i></button>'
            + '<button type="button" class="icon-btn" data-act="edit" data-i="' + i + '" title="تعديل"><i class="bi bi-pencil"></i></button>'
            + '<button type="button" class="icon-btn icon-btn--del" data-act="del" data-i="' + i + '" title="حذف"><i class="bi bi-trash3"></i></button>'
            + '</div></td></tr>';
        }
        tbody.innerHTML = html;
        Array.prototype.forEach.call(tbody.querySelectorAll("img"), function(img){
          img.addEventListener("error", function(){ img.style.display = "none"; });
        });
      }

      updateStats();
    }

    function updateStats(){
      var n = players.length;
      var sum = 0, top = 0;
      for(var i = 0; i < n; i++){
        var v = players[i].points || 0;
        sum += v;
        if(v > top) top = v;
      }
      var el;
      el = $("stTotal"); if(el) el.textContent = n;
      el = $("stTop");   if(el) el.textContent = top.toLocaleString();
      el = $("stAvg");   if(el) el.textContent = n ? Math.round(sum/n).toLocaleString() : "0";
      el = $("stSum");   if(el) el.textContent = sum.toLocaleString();
    }

    /* ---- FORM ---- */
    function resetForm(){
      editingIndex = -1;
      var f = $("playerForm");
      if(f) f.reset();
      var b = $("btnSubmit");
      if(b) b.innerHTML = '<i class="bi bi-plus-lg"></i> إضافة لاعب';
      var c = $("btnCancelEdit");
      if(c) c.style.display = "none";
      var ft = $("formTitle");
      if(ft) ft.textContent = "إضافة لاعب جديد";
      if(typeof setPreview === "function") setPreview("");
      render();
    }

    var form = $("playerForm");
    if(form){
      form.addEventListener("submit", function(e){
        e.preventDefault();
        var name = ($("fName").value || "").trim();
        var pts = parseInt($("fPoints").value, 10);

        if(!name){ toast("⚠️ أدخل اسم اللاعب"); return; }
        if(isNaN(pts) || pts < 0){ toast("⚠️ أدخل نقاطاً صحيحة"); return; }

        var badge = $("fBadge").value || "";
        var avatar = ($("fAvatar").value || "").trim();

        if(editingIndex >= 0 && editingIndex < players.length){
          players[editingIndex].name = name;
          players[editingIndex].points = pts;
          players[editingIndex].badge = badge;
          players[editingIndex].avatar = avatar;
          toast("✅ تم تعديل " + name);
        } else {
          players.push({ name: name, points: pts, badge: badge, avatar: avatar, rank: 0 });
          toast("✅ تمت إضافة " + name);
        }

        resetForm();
      });
    }

    /* ---- TABLE ACTIONS ---- */
    var tbody = $("tbody");
    if(tbody){
      tbody.addEventListener("click", function(e){
        var btn = e.target.closest ? e.target.closest("[data-act]") : null;
        if(!btn) return;
        var act = btn.getAttribute("data-act");
        var i = parseInt(btn.getAttribute("data-i"), 10);
        if(isNaN(i) || i < 0 || i >= players.length) return;

        if(act === "del"){
          var nm = players[i].name;
          players.splice(i, 1);
          if(editingIndex === i) resetForm();
          else if(editingIndex > i) editingIndex--;
          render();
          toast("🗑️ حُذف " + nm);
        }
        else if(act === "edit"){
          editingIndex = i;
          var p = players[i];
          $("fName").value = p.name || "";
          $("fPoints").value = p.points || 0;
          $("fBadge").value = p.badge || "";
          $("fAvatar").value = p.avatar || "";
          if(typeof setPreview === "function") setPreview(p.avatar || "");
          $("btnSubmit").innerHTML = '<i class="bi bi-check-lg"></i> حفظ التعديل';
          $("btnCancelEdit").style.display = "";
          $("formTitle").textContent = "تعديل: " + (p.name || "");
          render();
          $("fName").focus();
        }
        else if(act === "up"){
          if(i > 0){
            var tmp = players[i];
            players[i] = players[i-1];
            players[i-1] = tmp;
            if(editingIndex === i) editingIndex = i-1;
            else if(editingIndex === i-1) editingIndex = i;
            render();
            toast("⬆️ تم التحريك");
          }
        }
      });
    }

    var btnCancelEdit = $("btnCancelEdit");
    if(btnCancelEdit) btnCancelEdit.addEventListener("click", resetForm);

    /* ---- CLEAR ALL ---- */
    var btnClearAll = $("btnClearAll");
    if(btnClearAll) btnClearAll.addEventListener("click", function(){
      if(players.length === 0){ toast("القائمة فارغة أصلاً"); return; }
      if(confirm("هل أنت متأكد من مسح جميع اللاعبين؟")){
        players = [];
        resetForm();
        toast("🗑️ تم مسح الكل");
      }
    });

    /* ---- EXPORT ---- */
    var btnExport = $("btnExport");
    if(btnExport) btnExport.addEventListener("click", function(){
      if(players.length === 0){ toast("⚠️ لا توجد بيانات للتصدير"); return; }
      players.sort(function(a,b){ return (b.points||0) - (a.points||0); });
      players.forEach(function(p,i){ p.rank = i+1; });
      var blob = new Blob([JSON.stringify(players, null, 2)], {type:"application/json"});
      var a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "leaderboard.json";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(function(){ URL.revokeObjectURL(a.href); }, 1000);
      toast("📤 تم تصدير leaderboard.json");
    });

    /* ---- IMPORT ---- */
    var btnImport = $("btnImport");
    if(btnImport) btnImport.addEventListener("click", function(){ $("fileInput").click(); });

    var fileInput = $("fileInput");
    if(fileInput) fileInput.addEventListener("change", function(e){
      var file = e.target.files && e.target.files[0];
      if(!file) return;
      var reader = new FileReader();
      reader.onload = function(ev){
        try{
          var data = JSON.parse(ev.target.result);
          if(Array.isArray(data)){
            players = data;
            resetForm();
            toast("📥 استُورد " + data.length + " لاعب");
          } else {
            toast("⚠️ ملف غير صالح");
          }
        }catch(err){
          toast("⚠️ خطأ في قراءة الملف");
        }
      };
      reader.readAsText(file);
      e.target.value = "";
    });

    /* ---- SAMPLE DATA ---- */
    var btnSample = $("btnSample");
    if(btnSample) btnSample.addEventListener("click", function(){
      if(players.length > 0 && !confirm("استبدال البيانات الحالية ببيانات تجريبية؟")) return;
      players = [
        {name:"ShadowX",   points:9850, badge:"👑", avatar:"", rank:0},
        {name:"CyberWolf", points:8720, badge:"🥇", avatar:"", rank:0},
        {name:"ZeroCool",  points:7460, badge:"🥈", avatar:"", rank:0},
        {name:"NeonHacker",points:6890, badge:"🥉", avatar:"", rank:0},
        {name:"DarkPhoenix",points:5340,badge:"", avatar:"", rank:0},
        {name:"GhostByte", points:4810, badge:"", avatar:"", rank:0},
        {name:"CipherKing",points:3950, badge:"", avatar:"", rank:0},
        {name:"BinaryQueen",points:3200,badge:"", avatar:"", rank:0},
        {name:"NullPointer",points:2780,badge:"", avatar:"", rank:0},
        {name:"RootAccess",points:1960, badge:"", avatar:"", rank:0}
      ];
      resetForm();
      toast("✨ تم تحميل بيانات تجريبية");
    });

    /* ---- INIT ---- */
    load();
    render();

    /* ==================== GitHub API CLOUD ==================== */
    var GH_USER_KEY = "hs_gh_user";
    var GH_REPO_KEY = "hs_gh_repo";
    var GH_TOKEN_KEY = "hs_gh_token";
    var GH_API = "https://api.github.com";
    var GH_FILE_PATH = "data/leaderboard.json";
    var GH_BRANCH = "main";

    function ghUser(){ var el = $("ghUser"); return el ? el.value.trim() : ""; }
    function ghRepo(){ var el = $("ghRepo"); return el ? el.value.trim() : ""; }
    function ghToken(){ var el = $("ghToken"); return el ? el.value.trim() : ""; }

    function loadGhSettings(){
      try{
        var u = localStorage.getItem(GH_USER_KEY);
        var r = localStorage.getItem(GH_REPO_KEY);
        var t = localStorage.getItem(GH_TOKEN_KEY);
        if(u) $("ghUser").value = u;
        if(r) $("ghRepo").value = r;
        if(t) $("ghToken").value = t;
      }catch(e){}
    }

    function saveGhSettings(){
      try{
        localStorage.setItem(GH_USER_KEY, ghUser());
        localStorage.setItem(GH_REPO_KEY, ghRepo());
        localStorage.setItem(GH_TOKEN_KEY, ghToken());
      }catch(e){}
    }

    function ghHeaders(){
      return {
        "Authorization": "Bearer " + ghToken(),
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json"
      };
    }

    function ghFileUrl(){
      return GH_API + "/repos/" + ghUser() + "/" + ghRepo() + "/contents/" + GH_FILE_PATH;
    }

    /* ---- Load from GitHub ---- */
    var btnGhLoad = $("btnGhLoad");
    if(btnGhLoad) btnGhLoad.addEventListener("click", function(){
      if(!ghUser() || !ghRepo()){ toast("⚠️ أدخل Username و اسم المستودع"); return; }

      toast("⏳ جاري التحميل من GitHub...");
      // Try main branch first, then master
      fetch(ghFileUrl() + "?ref=" + GH_BRANCH)
        .then(function(r){
          if(!r.ok && GH_BRANCH === "main"){
            GH_BRANCH = "master";
            return fetch(ghFileUrl() + "?ref=master");
          }
          return r;
        })
        .then(function(r){ return r.json(); })
        .then(function(d){
          if(d && d.content){
            // GitHub returns base64 encoded content — decode UTF-8 properly
            var bstr = atob(d.content.replace(/\n/g, ""));
            var bytes = new Uint8Array(bstr.length);
            for(var i=0;i<bstr.length;i++){ bytes[i] = bstr.charCodeAt(i); }
            var decoded = new TextDecoder("utf-8").decode(bytes);
            var data = JSON.parse(decoded);
            if(Array.isArray(data)){
              players = data;
              resetForm();
              toast("✅ تحمّل " + players.length + " لاعب من GitHub");
            } else {
              toast("❌ البيانات ليست مصفوفة");
            }
          } else if(d && d.message){
            toast("❌ خطأ: " + d.message);
          } else {
            toast("❌ لم يُعثر على الملف");
          }
        })
        .catch(function(err){ toast("❌ خطأ: " + err.message); });
    });

    /* ---- Save to GitHub ---- */
    var btnGhSave = $("btnGhSave");
    if(btnGhSave) btnGhSave.addEventListener("click", function(){
      if(!ghUser() || !ghRepo() || !ghToken()){ toast("⚠️ أدخل جميع البيانات أولاً"); return; }
      if(players.length === 0){ toast("⚠️ لا توجد بيانات للحفظ"); return; }

      // Sort and rank
      players.sort(function(a,b){ return (b.points||0) - (a.points||0); });
      players.forEach(function(p,i){ p.rank = i+1; });
      render();

      var json = JSON.stringify(players, null, 2);
      var b64 = btoa(unescape(encodeURIComponent(json)));
      toast("⏳ جاري الحفظ في GitHub...");

      // Step 1: Get current file SHA (required for update)
      fetch(ghFileUrl() + "?ref=" + GH_BRANCH, { headers: ghHeaders() })
        .then(function(r){
          if(!r.ok && GH_BRANCH === "main"){
            GH_BRANCH = "master";
            return fetch(ghFileUrl() + "?ref=master", { headers: ghHeaders() });
          }
          return r;
        })
        .then(function(r){ return r.json(); })
        .then(function(fileData){
          var sha = fileData && fileData.sha ? fileData.sha : undefined;

          // Step 2: Create or update file
          var body = {
            message: "🏆 Update leaderboard — " + new Date().toLocaleString(),
            content: b64,
            branch: GH_BRANCH
          };
          if(sha) body.sha = sha;

          return fetch(ghFileUrl(), {
            method: "PUT",
            headers: ghHeaders(),
            body: JSON.stringify(body)
          });
        })
        .then(function(r){ return r.json(); })
        .then(function(d){
          if(d && d.commit && d.commit.sha){
            saveGhSettings();
            toast("✅ تم الحفظ! Commit: " + d.commit.sha.substring(0,7) + " — Netlify سيعيد النشر تلقائياً");
          } else if(d && d.message){
            toast("❌ خطأ: " + d.message);
          } else {
            toast("❌ رد غير متوقع");
          }
        })
        .catch(function(err){ toast("❌ خطأ: " + err.message); });
    });

    // Auto-save settings on input change
    ["ghUser","ghRepo","ghToken"].forEach(function(id){
      var el = $(id);
      if(el) el.addEventListener("change", saveGhSettings);
    });

    // Load saved settings on startup
    loadGhSettings();

    /* ---- DISCORD HELP MODAL ---- */
    var discordModal = $("discordHelpModal");
    var btnDiscordHelp = $("btnDiscordHelp");

    function closeModal(){ if(discordModal) discordModal.classList.remove("open"); }

    if(btnDiscordHelp && discordModal){
      btnDiscordHelp.addEventListener("click", function(){ discordModal.classList.add("open"); });
      discordModal.addEventListener("click", function(e){
        if(e.target === discordModal) closeModal();
        if(e.target.closest && e.target.closest("[data-close-modal]")) closeModal();
      });
      document.addEventListener("keydown", function(e){ if(e.key === "Escape") closeModal(); });
    }

    /* ---- AVATAR UPLOAD + PREVIEW ---- */
    var fAvatar = $("fAvatar");
    var fAvatarFile = $("fAvatarFile");
    var btnPickAvatar = $("btnPickAvatar");
    var btnClearAvatar = $("btnClearAvatar");
    var avatarPreview = $("avatarPreview");

    function setPreview(src){
      if(!avatarPreview) return;
      if(src){
        avatarPreview.innerHTML = '<img src="' + escAttr(String(src)) + '" alt="">';
        var _pimg = avatarPreview.querySelector("img");
        if(_pimg) _pimg.addEventListener("error", function(){ _pimg.style.display = "none"; });
        avatarPreview.classList.add("has-img");
        if(btnClearAvatar) btnClearAvatar.style.display = "";
      } else {
        avatarPreview.innerHTML = '<i class="bi bi-person-fill"></i>';
        avatarPreview.classList.remove("has-img");
        if(btnClearAvatar) btnClearAvatar.style.display = "none";
      }
    }

    if(btnPickAvatar && fAvatarFile){
      btnPickAvatar.addEventListener("click", function(){ fAvatarFile.click(); });

      fAvatarFile.addEventListener("change", function(){
        var file = fAvatarFile.files && fAvatarFile.files[0];
        if(!file) return;
        if(!/^image\//.test(file.type)){ toast("⚠️ اختر ملف صورة"); return; }
        if(file.size > 8 * 1024 * 1024){ toast("⚠️ الصورة كبيرة جداً (الحد 8MB)"); return; }

        var reader = new FileReader();
        reader.onload = function(ev){
          var img = new Image();
          img.onload = function(){
            var MAX = 160;
            var side = Math.min(img.width, img.height);
            var sx = (img.width - side) / 2;
            var sy = (img.height - side) / 2;
            var out = Math.min(side, MAX) || MAX;

            var canvas = document.createElement("canvas");
            canvas.width = out; canvas.height = out;
            var ctx = canvas.getContext("2d");
            ctx.drawImage(img, sx, sy, side, side, 0, 0, out, out);

            var dataUrl = canvas.toDataURL("image/jpeg", 0.82);
            if(fAvatar) fAvatar.value = dataUrl;
            setPreview(dataUrl);
            toast("✅ تم تحميل الصورة (" + Math.round(dataUrl.length / 1024) + " KB)");
          };
          img.onerror = function(){ toast("❌ تعذّر قراءة الصورة"); };
          img.src = ev.target.result;
        };
        reader.onerror = function(){ toast("❌ خطأ في قراءة الملف"); };
        reader.readAsDataURL(file);
      });
    }

    if(btnClearAvatar){
      btnClearAvatar.addEventListener("click", function(){
        if(fAvatar) fAvatar.value = "";
        if(fAvatarFile) fAvatarFile.value = "";
        setPreview("");
      });
    }

    if(fAvatar){
      var avatarTimer = null;
      fAvatar.addEventListener("input", function(){
        var v = fAvatar.value.trim();
        // Instant preview for data URLs (uploaded images)
        if(v.indexOf("data:image/") === 0){ setPreview(v); return; }
        clearTimeout(avatarTimer);
        avatarTimer = setTimeout(function(){ setPreview(fAvatar.value.trim()); }, 700);
      });
    }

  })();
