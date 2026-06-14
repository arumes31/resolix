# Font Files

This directory should contain the following WOFF2 font files:

- `Outfit-Regular.woff2`
- `Outfit-Medium.woff2`
- `Outfit-SemiBold.woff2`
- `Outfit-Bold.woff2`
- `Inter-Regular.woff2`
- `Inter-Medium.woff2`
- `Inter-SemiBold.woff2`
- `Inter-Bold.woff2`

## How to Obtain the Font Files

### Option 1: Download from Google Fonts API

Visit these URLs in a browser and download the font files:

- **Outfit**: https://fonts.google.com/specimen/Outfit
- **Inter**: https://fonts.google.com/specimen/Inter

Click "Download family" on each page, extract the ZIP, and convert TTF files
to WOFF2 format using a tool like `woff2_compress` or an online converter.

### Option 2: Use the Google Fonts CSS API to find direct WOFF2 URLs

1. Open a browser with a US-based IP address
2. Visit: `https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap`
3. View the page source to find the `src: url(...)` references to WOFF2 files on `fonts.gstatic.com`
4. Download each WOFF2 file and place it in this directory

### Option 3: Use command-line tools

```bash
# Install woff2 tool
# On Ubuntu/Debian: sudo apt install woff2
# On macOS: brew install woff2

# Download from Google Fonts GitHub releases
# https://github.com/google/fonts/tree/main/ofl/outfit
# https://github.com/google/fonts/tree/main/ofl/inter

# Convert TTF to WOFF2
woff2_compress Outfit-Regular.ttf
woff2_compress Outfit-Medium.ttf
woff2_compress Outfit-SemiBold.ttf
woff2_compress Outfit-Bold.ttf
woff2_compress Inter-Regular.ttf
woff2_compress Inter-Medium.ttf
woff2_compress Inter-SemiBold.ttf
woff2_compress Inter-Bold.ttf
```

## Important

The `fonts.css` file references these WOFF2 files by relative path. Ensure all
8 files are present before building the application, otherwise the embedded
static file system will not include them and fonts will fail to load.
