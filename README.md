# Stored XSS via Newsletter Title in modified eCommerce Shopsoftware `admin/module_newsletter.php`

> **Identifier:** CVE pending
> **Affected:** modified eCommerce Shopsoftware ≤ 3.3.0 (rev 16825) — including current `main` as of 2026-11-19
> **Severity:** Medium · **CVSS 3.1:** 4.8 — `AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`
> **CWE:** CWE-79 (Stored XSS)
> **Status:** Unpatched
> **Vendor notified:** 2026-11-19 — [modified-shop/modified-shop#ISSUE](https://github.com/modified-shop/modified-shop/issues/ISSUE)

---

## Summary

The admin Newsletter module stores the newsletter `title` using `xtc_db_prepare_input()` (which only does `trim()` + `stripslashes()`) and echoes it in the newsletter listing **without `htmlspecialchars()`**. An admin who saves a malicious title stores a script that executes in the browser of every admin who opens the Newsletter listing — session cookie / CSRF-token theft.

Verified in the current `main` branch (2026-11-19): the file contains zero `htmlspecialchars()` calls; `title` is echoed raw at lines 338 and 425 (and 366).

## Affected

| Component | Versions | Status |
|---|---|---|
| `admin/module_newsletter.php` (lines 36, 338, 425) | ≤ 3.3.0 rev 16825 → current `main` | Affected |

Repository: https://github.com/modified-shop/modified-shop · Evaluated stack: PHP 8.1.34, Apache 2.4, MariaDB 10.6 (authorized Docker lab).

## Vulnerable code

```php
// admin/module_newsletter.php:36 — stored with no HTML encoding:
$title = xtc_db_prepare_input($_POST['title']);   // trim() + stripslashes() only

// :338 and :425 — displayed without htmlspecialchars():
<b><?php echo $news_data[$i]['title']; ?></b>
```

## Evidence (lab)

Inject (admin, POST `title=<script>...</script>`, `action=new_newsletter`) → open the Newsletter listing:

```html
<b><script>alert(document.cookie)</script></b>
```

Confirmed in authorized lab; PoC with login/CSRF handling and cleanup in [`poc.sh`](poc.sh). Detection: `SELECT newsletters_id, title FROM newsletters WHERE title LIKE '%<%';`

## Fix

```php
// admin/module_newsletter.php:338,425 (and :366)
echo htmlspecialchars($news_data[$i]['title'], ENT_QUOTES, 'UTF-8');
```

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-11-16 | Identified via code review |
| 2026-11-19 | Verified still unpatched in `main` |
| 2026-11-19 | Advisory + PoC published (this repository) |
| 2026-11-19 | Vendor notified via GitHub issue |
| pending | CVE requested |

## Credits

- **Researchers:** Fernando Viana & Marcus Chaves
- **Contact:** nanduviana@gmail.com

## References

- Vendor notification: (issue link added on submission)
- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- Vendor repository: https://github.com/modified-shop/modified-shop

---

*This advisory is published for educational, defensive, and security improvement purposes.*
