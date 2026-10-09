markdown
# 📖 Clicker — Usage Examples

دليل شامل لكل الـ CLI options مع أمثلة عملية.

---

## 📑 Table of Contents

- [Basic Options](#-basic-options)
- [Target Options](#-target-options)
- [Scope Options](#-scope-options)
- [Output & Report Options](#-output--report-options)
- [Program Policy Options](#-program-policy-options)
- [IDOR Options](#-idor-options)
- [Playwright Options](#-playwright-options)
- [Authentication Options](#-authentication-options)
- [Mode Options](#-mode-options)
- [Proxy Options](#-proxy-options)
- [Wordlist & Resolvers](#-wordlist--resolvers)
- [Other Options](#-other-options)
- [Combined Examples](#-combined-examples)

---

## 🔧 Basic Options

### `-h, --help`

عرض قائمة كل الخيارات المتاحة.

```bash
python3 clicker.py -h
python3 clicker.py --help
```

---

## 🎯 Target Options

### `-t, --target <domain>`

تحديد هدف واحد.

```bash
# هدف واحد
python3 clicker.py -t example.com

# هدف مع port
python3 clicker.py -t example.com:8443

# هدف مع verbose
python3 clicker.py -t example.com -v
```

### `--targets-file <file>`

ملف فيه أهداف متعددة (سطر لكل هدف).

```bash
# الملف: targets.txt
# example.com
# test.com
# api.example.com
# 192.168.1.1
# juice.local:3000

python3 clicker.py --targets-file targets.txt -v
```

**ملاحظة:** السطور الفارغة والتي تبدأ بـ `#` يتم تجاهلها.

---

## 🎯 Scope Options

### `--scope-file <file>`

ملف يحدد نطاق الفحص (مدى/لا مدى).

```bash
# الملف: scope.txt
# *.example.com
# example.com
# !blog.example.com
# !*.cdn.example.com

python3 clicker.py --targets-file targets.txt --scope-file scope.txt
```

**القواعد:**
- أي سطر عادي = مسموح (in-scope)
- أي سطر يبدأ بـ `!` = ممنوع (out-of-scope)
- يدعم wildcard: `*.example.com`

---

## 📁 Output & Report Options

### `--workspace <dir>`

تحديد مجلد المخرجات (default: `clicker_output`).

```bash
python3 clicker.py -t example.com --workspace my_scans

# مخرجات في: my_scans/example.com/...
```

### `--report-format {txt,html,both}`

شكل التقرير النهائي.

```bash
# نصي فقط
python3 clicker.py -t example.com --report-format txt

# HTML فقط
python3 clicker.py -t example.com --report-format html

# الاثنين (default)
python3 clicker.py -t example.com --report-format both
```

**المخرجات:**
- `report.json` — دائماً يُنتَج
- `report.txt` — إذا txt أو both
- `report.html` — إذا html أو both

### `--api-file <file>`

ملف API keys (default: `clicker_api.env`).

```bash
python3 clicker.py -t example.com --api-file my_keys.env
```

**صيغة الملف:**
```
CHAOS_API_KEY=xxx
VT_API_KEY=xxx
GITHUB_TOKEN=xxx
SHODAN_API=xxx
LEAKIX_API=xxx
```

---

## 📋 Program Policy Options

### `--program-setup`

إعادة تشغيل wizard إعداد program policy (rate limits, headers, notes).

```bash
# تشغيل الـ wizard يدوياً
python3 clicker.py -t example.com --program-setup

# الـ wizard يسأل:
# 1. Paste program page text (A) أو Manual (B)
# 2. HTTP headers مخصصة
# 3. Rate limit (req/s)
# 4. Extra flags
# 5. Notes
```

**يُحفظ في:** `programs/<domain>.json`

---

## 🎯 IDOR Options

### `--idor-login-url <url>`

تحديد URL الـ login يدوياً (بدل auto-discovery).

```bash
python3 clicker.py -t example.com --idor-only \
  --idor-login-url "https://api.example.com/auth/login"
```

**متى تستخدمه:**
- الـ auto-discovery فشل
- الـ endpoint غير معتاد
- هدف Flutter/SPA مع custom auth

### `--idor-login-json <json>`

تحديد body الـ login (JSON) مع placeholders `%EMAIL%` و `%PASS%`.

```bash
python3 clicker.py -t example.com --idor-only \
  --idor-login-url "https://api.example.com/login" \
  --idor-login-json '{"email":"%EMAIL%","password":"%PASS%"}'
```

**أمثلة لأشكال مختلفة:**

```bash
# بسيط
--idor-login-json '{"email":"%EMAIL%","password":"%PASS%"}'

# مع wrapper
--idor-login-json '{"data":{"email":"%EMAIL%","password":"%PASS%"}}'

# Firebase
--idor-login-json '{"data":{"email":"%EMAIL%","password":"%PASS%","deviceToken":null,"deviceId":"web_client","deviceName":"Web App"}}'

# مع حقول إضافية
--idor-login-json '{"username":"%EMAIL%","pass":"%PASS%","remember":true}'
```

---

## 🕷️ Playwright Options

### `--idor-pw`

تشغيل Playwright لالتقاط الـ network traffic (headless default).

```bash
python3 clicker.py -t example.com --idor-only --idor-pw
```

### `--idor-pw-duration <seconds>`

مدة الالتقاط بالثواني (default: 30).

```bash
# التقاط 60 ثانية
python3 clicker.py -t example.com --idor-only --idor-pw --idor-pw-duration 60
```

### `--idor-pw-headless`

تشغيل Playwright في وضع headless (default، المتصفح مخفي).

```bash
python3 clicker.py -t example.com --idor-only \
  --idor-pw --idor-pw-headless
```

### `--idor-pw-visible`

تشغيل Playwright في وضع مرئي (المتصفح يظهر).

```bash
python3 clicker.py -t example.com --idor-only \
  --idor-pw-visible \
  --idor-login-url "https://api.example.com/login" \
  --idor-login-json '{"email":"%EMAIL%","password":"%PASS%"}'
```

**متى تستخدمه:**
- تريد تسجيل دخول يدوي
- تريد تصفح الموقع
- SPA يحتاج تفاعل بشري

**Auto-close:** المتصفح يُغلق تلقائياً بعد:
- 15s minimum
- login URL + 3 API calls
- 8s هدوء
- أو 180s max

### `--idor-pw-follow-links`

اتباع الروابط الداخلية أثناء الالتقاط.

```bash
python3 clicker.py -t example.com --idor-only \
  --idor-pw --idor-pw-follow-links
```

---

## 🔐 Authentication Options

### `--idor-a-email <email>` + `--idor-a-pass <pass>`

بيانات Account A (المُهاجم).

### `--idor-b-email <email>` + `--idor-b-pass <pass>`

بيانات Account B (الضحية).

```bash
python3 clicker.py -t example.com --idor-only \
  --idor-a-email "attacker@example.com" \
  --idor-a-pass "PassA123!" \
  --idor-b-email "victim@example.com" \
  --idor-b-pass "PassB123!"
```

**مهم:** لازم حسابين حقيقيين مُسجلين على الهدف.

---

## 🎛️ Mode Options

### `--no-profile`

تخطي program profile wizard واستخدام defaults.

```bash
python3 clicker.py -t example.com --no-profile
```

**متى تستخدمه:**
- للسكان السريع
- هدف اختبار
- ما تريد حفظ إعدادات

### `--idor-only`

تشغيل IDOR phase فقط (تخطي كل المراحل الأخرى).

```bash
python3 clicker.py -t example.com --idor-only \
  --idor-a-email "a@x.com" --idor-a-pass "xxx" \
  --idor-b-email "b@x.com" --idor-b-pass "xxx"
```

**متى تستخدمه:**
- الـ recon خلص سابقاً
- تريد تركيز على IDOR فقط
- عندك login credentials جاهزة

---

## 🔄 Resume/Fallback Options

### `--resume`

متابعة السكان من آخر checkpoint.

```bash
# إذا السكان توقف
python3 clicker.py -t example.com --resume
```

**الـ checkpoint:** `clicker_output/.clicker_resume.json`

### `--force`

إجبار السكان حتى لو Quick Probe قال الهدف ميت.

```bash
python3 clicker.py -t example.com --force
```

**متى تستخدمه:**
- DNS بطيء
- هدف local/offline
- HTTPS بس (HTTP ميت)

---

## 🌐 Proxy Options

### `--proxy <proxy>`

بروكسي واحد.

```bash
# HTTP
python3 clicker.py -t example.com --proxy "185.162.128.45:8080"

# مع auth
python3 clicker.py -t example.com --proxy "user:pass@185.162.128.45:8080"

# SOCKS5
python3 clicker.py -t example.com --proxy "socks5://127.0.0.1:1080"
```

### `--proxy-list <file>`

ملف فيه قائمة بروكسيات.

```bash
# الملف: proxies.txt
# 185.162.128.45:8080
# user:pass@45.12.34.56:9090
# socks5://127.0.0.1:1080

python3 clicker.py -t example.com --proxy-list proxies.txt
```

### `--auto-proxy`

جلب بروكسيات حديثة من APIs عامة.

```bash
python3 clicker.py -t example.com --auto-proxy
```

**المصادر:**
- `proxyscrape.com`
- `TheSpeedX/SOCKS-List`

### `--rotate-proxy`

تدوير البروكسي لكل هدف.

```bash
python3 clicker.py --targets-file targets.txt \
  --proxy-list proxies.txt --rotate-proxy
```

### `--proxychains`

توجيه كل الأدوات عبر proxychains4.

```bash
python3 clicker.py -t example.com --proxychains
```

**ملاحظة:** يحتاج `proxychains4` مثبت + config صحيح.

### `--hybrid-proxy`

ذكي: passive tools مباشر، active tools عبر proxy.

```bash
python3 clicker.py -t example.com --hybrid-proxy
```

**المنطق:**
```
Passive tools  (subfinder, gau)  → DIRECT  (أسرع)
Active tools   (httpx, nuclei)   → PROXY   (مجهول)
Network tools  (nmap, naabu)     → DIRECT  (تنظيف env)
```

**الاستخدام المثالي:**
```bash
python3 clicker.py -t example.com \
  --auto-proxy --rotate-proxy --hybrid-proxy
```

---

## 📚 Wordlist & Resolvers

### `--wordlist <file>`

قائمة كلمات للـ bruteforce.

```bash
python3 clicker.py -t example.com \
  --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

### `--resolvers <file>`

ملف resolvers للـ DNS.

```bash
python3 clicker.py -t example.com \
  --resolvers /usr/share/seclists/Discovery/DNS/resolvers.txt
```

**متى تستخدمهما:**
- تريد wordlist مخصص
- resolvers أسرع
- الوضع الافتراضي لا يعمل

---

## 🔧 Other Options

### `--keep-sources`

الاحتفاظ بالملفات الوسيطة (default: تُحذف).

```bash
python3 clicker.py -t example.com --keep-sources
```

**متى تستخدمه:**
- debugging
- تحليل متقدم
- دمج مع أدوات أخرى

### `-v, --verbose`

عرض تفصيلي لكل خطوة.

```bash
python3 clicker.py -t example.com -v
python3 clicker.py -t example.com --verbose
```

**ما يعرض:**
- كل أمر يُنفَّذ
- محتوى الملفات المهمة
- نتائج كل مرحلة بالتفصيل
- AI decisions

---

## 🎯 Combined Examples

### 1. فحص أساسي سريع

```bash
python3 clicker.py -t example.com -v
```

### 2. فحص متعدد الأهداف

```bash
python3 clicker.py --targets-file targets.txt --report-format both -v
```

### 3. فحص مع scope

```bash
python3 clicker.py \
  --targets-file targets.txt \
  --scope-file scope.txt \
  -v
```

### 4. IDOR فقط مع authentication

```bash
python3 clicker.py -t example.com --idor-only \
  --idor-a-email "attacker@x.com" --idor-a-pass "PassA" \
  --idor-b-email "victim@x.com" --idor-b-pass "PassB" \
  -v
```

### 5. IDOR مع custom login endpoint

```bash
python3 clicker.py -t example.com --idor-only \
  --idor-login-url "https://api.example.com/auth/login" \
  --idor-login-json '{"email":"%EMAIL%","password":"%PASS%"}' \
  --idor-a-email "a@x.com" --idor-a-pass "PassA" \
  --idor-b-email "b@x.com" --idor-b-pass "PassB"
```

### 6. IDOR على SPA/Flutter (Playwright)

```bash
python3 clicker.py -t example.com --idor-only \
  --idor-pw-visible \
  --idor-login-url "https://api.example.com/login" \
  --idor-login-json '{"data":{"email":"%EMAIL%","password":"%PASS%"}}' \
  --idor-a-email "a@x.com" --idor-a-pass "PassA" \
  --idor-b-email "b@x.com" --idor-b-pass "PassB" \
  -v
```

### 7. فحص مجهول مع proxy

```bash
python3 clicker.py -t example.com \
  --auto-proxy --rotate-proxy --hybrid-proxy \
  --report-format both
```

### 8. تحدي WAF (Cloudflare/Akamai)

```bash
python3 clicker.py -t example.com \
  --hybrid-proxy \
  --report-format both -v
```

### 9. هدف local (Juice Shop/crAPI)

```bash
python3 clicker.py -t 127.0.0.1.nip.io:3000 --idor-only \
  --idor-a-email "test@test.com" --idor-a-pass "Test123!" \
  --idor-b-email "victim@test.com" --idor-b-pass "Test123!" \
  -v
```

### 10. متابعة سكان توقف

```bash
python3 clicker.py -t example.com --resume -v
```

### 11. برنامج bug bounty بميزات مخصصة

```bash
python3 clicker.py -t example.com \
  --program-setup \
  --scope-file scope.txt \
  --report-format both \
  -v
```

### 12. تخزين مخرجات في مكان مخصص

```bash
python3 clicker.py -t example.com \
  --workspace scans/2026-10-09 \
  --keep-sources \
  -v
```

### 13. Brute force مع wordlist مخصص

```bash
python3 clicker.py -t example.com \
  --wordlist /path/to/my-wordlist.txt \
  --resolvers /path/to/resolvers.txt \
  -v
```

### 14. سكان كامل كل شي

```bash
python3 clicker.py -t example.com \
  --program-setup \
  --auto-proxy --hybrid-proxy \
  --report-format both \
  --keep-sources \
  -v
```

### 15. ملف scope كامل + proxy + IDOR

```bash
python3 clicker.py \
  --targets-file targets.txt \
  --scope-file scope.txt \
  --auto-proxy --rotate-proxy --hybrid-proxy \
  --idor-only \
  --idor-login-url "https://api.example.com/login" \
  --idor-login-json '{"email":"%EMAIL%","password":"%PASS%"}' \
  --idor-a-email "a@x.com" --idor-a-pass "PassA" \
  --idor-b-email "b@x.com" --idor-b-pass "PassB" \
  --report-format both \
  -v
```

---

## 💡 Tips

### ✅ Best Practices

1. **استخدم `-v` دائماً** — يخليك تشوف شنو يصير
2. **احفظ الـ scope** — قانونياً مهم
3. **`--hybrid-proxy` مع `--auto-proxy`** — أفضل مزيج للـ stealth
4. **`--report-format both`** — للـ archival
5. **`--keep-sources`** — إذا تريد تحلل لاحقاً

### ⚠️ احتياطات

- **`--force`** — استخدمه بحذر (يكمل على هدف ميت)
- **`--program-setup`** — يعيد كتابة الـ profile (احفظ القديم)
- **IDOR credentials** — استخدم حسابات تجريبية، مو حقيقية
- **`--auto-proxy`** — البروكسيات العامة غير موثوقة

### 🔥 Common Errors

**`unrecognized arguments: --skip-*`**
> استخدم ask_phase prompts بدلها

**`invalid domain`**
> استخدم `domain.com` بدون `http://` أو `https://`

**`No profile found`**
> أضف `--no-profile` للسكان السريع

**`Auto-login failed`**
> استخدم `--idor-login-url` + `--idor-login-json`

---

## 📚 Related Docs

- **`README.md`** — نظرة عامة على المشروع
- **`CHANGELOG.md`** — تاريخ التغييرات
- **`BYPASS_CHECKLIST.md`** — IDOR bypass techniques

---

**Built with ❤️ by [@403_linux](https://instagram.com/403_linux)**
```
