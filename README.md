# MasterStudy Secure Attachments (v2 — no migration)

Fixes the security vulnerability where MasterStudy LMS Pro lesson attachments are publicly accessible via their direct URL in `/wp-content/uploads/`.

## Key Difference from Version 1

This version **does not move any files or touch the database** (`wp_postmeta`, attachment paths, etc.). It is a much less invasive approach:

1. Blocks direct access **only for the file extensions you use in courses** (`pdf`, `doc`, `docx`, `xls`, `xlsx`, `zip`, `txt`) inside `wp-content/uploads/`, via `.htaccess`. Images and other media on your site will continue to work as usual.
2. Files remain in their original location — the secure controller reads them directly from there.
3. Automatically rewrites direct links to protected files **on the fly in the output HTML** (without modifying the database) on course/lesson pages, replacing them with the secure URL (`?mssa_file=ID`).
4. Upon deactivating the plugin, it only removes the block of rules added to `.htaccess` — any existing rules remain intact.

## What It DOES Modify

- The `.htaccess` file inside `wp-content/uploads/` — it appends a block of rules delimited by comments (`# BEGIN MSSA...` / `# END MSSA...`), without deleting existing content.

## What It DOES NOT Modify

- Does not move files.
- Does not modify `wp_postmeta`, `wp_posts`, or any MasterStudy database tables.
- Does not change the `attachment_id` of any file.
- Fully reversible by deactivating the plugin.

## Installation

1. Upload the `ms-secure-attachments` folder to `wp-content/plugins/`.
2. Activate it from the WordPress Admin Dashboard.
3. Upon activation, it automatically adds the extension-based blocking rules to the `uploads` `.htaccess` file.
4. Purge the LiteSpeed Cache and Cloudflare cache to ensure you are seeing real-time behavior rather than a cached version.
5. Test: Open a lesson containing an attached file logged in as a user who purchased the course — the download button should function properly (pointing internally to the secure URL).
6. Test in Incognito mode or logged in as a user without access — direct access attempts should return a 403 Forbidden error.

## About Automatic Link Rewriting (Point 3)

MasterStudy outputs the lesson material download link into the lesson page HTML. Because the exact location where it is rendered is variable (could be via `the_content`, a shortcode, or a custom template), the plugin uses two combined mechanisms:

- A filter on `the_content` (handles the most common case).
- An output buffer (`ob_start`) active **only on URLs containing "course", "curso", or "mi-cuenta"** — avoiding any impact on the rest of the site — which scans the page HTML for links to protected files and replaces them with secure URLs.

**If the download button in a lesson stops working or continues showing the unprotected URL**, MasterStudy is likely generating that URL via an AJAX/API request rather than full page HTML. In that case, let me know so we can update the detection pattern (likely intercepting the specific REST/AJAX endpoint used by the curriculum editor).

## Protected Extensions

Configured in the `MSSA_PROTECTED_EXTENSIONS` constant at the top of the main plugin file:

```php
define( 'MSSA_PROTECTED_EXTENSIONS', array( 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'txt' ) );
```

If you start uploading other file types as course materials (e.g., `.pptx`, `.mp4`), add them to this array and re-activate the plugin (deactivate + activate) to update `.htaccess`.

## Cloudflare and LiteSpeed Cache

`nocache_headers()` prevents download responses from being cached. Nevertheless, purge the cache manually after initial plugin activation.

## Paid Memberships Pro

Uses the native `pmpro_has_membership_access()` function to check access permissions for both the course and individual lessons (in this setup, PMPro registers restrictions per lesson rather than per course — verified via Query Monitor).
