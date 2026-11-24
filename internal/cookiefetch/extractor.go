// Package cookiefetch provides a multi-format cookie extractor.
// Supports: .txt (Netscape/JSON/raw/multi-line), .json, .zip, .rar archives (nested).
package cookiefetch

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/nfchecker/internal/models"
)

const (
	maxZipFiles             = 50000
	maxZipFileSize          = 64 * 1024 * 1024  // 64MB per file
	maxZipTotalUncompressed = 512 * 1024 * 1024 // 512MB total
)

// ExtractFromFile accepts a path to a .txt, .json, .zip or .rar file
// (or a directory) and returns all discovered CookieSets.
func ExtractFromFile(path string) ([]*models.CookieSet, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return extractFromDir(path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return extractFromBytes(path, raw)
}

// ExtractFromReader accepts raw bytes with a filename hint.
func ExtractFromReader(name string, data []byte) ([]*models.CookieSet, error) {
	return extractFromBytes(name, data)
}

func extractFromBytes(name string, data []byte) ([]*models.CookieSet, error) {
	// Trust the bytes before the extension: exports get renamed, and a .txt
	// that is really a zip (or the reverse) used to yield zero cookies.
	switch {
	case len(data) >= 4 && data[0] == 'P' && data[1] == 'K' && (data[2] == 3 || data[2] == 5):
		return extractZip(data)
	case len(data) >= 7 && string(data[:7]) == "Rar!\x1a\x07\x00":
		return extractRar(data)
	case len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b:
		if plain, err := gunzip(data); err == nil {
			return extractText(name, plain)
		}
	}

	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".zip":
		return extractZip(data)
	case ".rar":
		return extractRar(data)
	default:
		return extractText(name, data)
	}
}

// gunzip expands a gzip stream so .gz cookie exports are understood too.
func gunzip(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(io.LimitReader(zr, maxZipFileSize))
}

// cookieLine trims a Netscape line and drops the "#HttpOnly_" marker Chrome
// and Edge put in front of HttpOnly cookies. NetflixId and SecureNetflixId are
// both HttpOnly, so treating those lines as comments hid every real cookie.
func cookieLine(raw string) (string, bool) {
	line := strings.TrimSpace(raw)
	if line == "" {
		return "", false
	}
	if strings.HasPrefix(line, "#HttpOnly_") {
		return strings.TrimSpace(strings.TrimPrefix(line, "#HttpOnly_")), true
	}
	if strings.HasPrefix(line, "#") {
		return "", false
	}
	return line, true
}

func extractFromDir(dir string) ([]*models.CookieSet, error) {
	var all []*models.CookieSet
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		raw, e2 := os.ReadFile(path)
		if e2 != nil {
			return nil
		}
		sets, _ := extractFromBytes(path, raw)
		all = append(all, sets...)
		return nil
	})
	return all, err
}

func extractZip(data []byte) ([]*models.CookieSet, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}

	var all []*models.CookieSet
	var totalBytes int64
	fileCount := 0

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		fileCount++
		if fileCount > maxZipFiles {
			break
		}

		// Prevent zip-slip
		cleaned := filepath.Clean(f.Name)
		if strings.HasPrefix(cleaned, "..") || filepath.IsAbs(cleaned) {
			continue
		}

		if f.UncompressedSize64 > maxZipFileSize {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		lr := io.LimitReader(rc, maxZipFileSize)
		inner, err := io.ReadAll(lr)
		rc.Close()
		if err != nil {
			continue
		}

		totalBytes += int64(len(inner))
		if totalBytes > maxZipTotalUncompressed {
			break
		}

		sets, _ := extractFromBytes(f.Name, inner)
		all = append(all, sets...)
	}
	return all, nil
}

func extractRar(data []byte) ([]*models.CookieSet, error) {
	tmp, err := os.CreateTemp("", "nfc_*.rar")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(data); err != nil {
		return nil, err
	}
	tmp.Close()

	outDir, err := os.MkdirTemp("", "nfc_rar_*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(outDir)

	// Safe command execution without shell injection (fallback order: bsdtar -> 7z -> unrar)
	if err := safeExec("bsdtar", "-xf", tmp.Name(), "-C", outDir); err != nil {
		if err2 := safeExec("7z", "x", "-y", tmp.Name(), "-o"+outDir); err2 != nil {
			_ = safeExec("unrar", "x", "-y", tmp.Name(), outDir+"/")
		}
	}

	return extractFromDir(outDir)
}

func extractText(name string, data []byte) ([]*models.CookieSet, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil
	}

	// Every parser runs and the results are merged. Returning after the first
	// parser that matched anything used to leave the rest of a mixed export
	// unchecked, which looked like the checker skipping part of the file.
	var sets []*models.CookieSet
	if found, ok := tryJSONArray(trimmed); ok {
		sets = append(sets, found...)
	}
	if cs, ok := trySingleJSON(trimmed); ok {
		sets = append(sets, cs)
	}
	sets = append(sets, tryNetscape(trimmed)...)
	sets = append(sets, tryMultiLineRaw(trimmed)...)
	return dedupeSets(sets), nil
}

// dedupeSets drops a cookie seen twice, keeping the order of first sight.
func dedupeSets(sets []*models.CookieSet) []*models.CookieSet {
	if len(sets) < 2 {
		return sets
	}
	seen := make(map[string]bool, len(sets))
	out := sets[:0]
	for _, cs := range sets {
		if cs == nil || cs.NetflixId == "" {
			continue
		}
		if cs.Fingerprint == "" {
			fingerprint(cs)
		}
		if seen[cs.Fingerprint] {
			continue
		}
		seen[cs.Fingerprint] = true
		out = append(out, cs)
	}
	return out
}

// newLineScanner reads lines of any realistic length. bufio.Scanner's 64KB
// default ended the scan silently in the middle of a long export, so the rest
// of the file was never parsed and never checked.
func newLineScanner(r io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 32*1024*1024)
	return scanner
}

func tryJSONArray(data []byte) ([]*models.CookieSet, bool) {
	if !bytes.HasPrefix(data, []byte("[")) {
		return nil, false
	}

	// Case A: array of {name, value} cookie items (e.g. browser extension export)
	var pairs []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(data, &pairs); err == nil && len(pairs) > 0 {
		// Group into sets if multiple NetflixIds exist
		var sets []*models.CookieSet
		currentMap := make(map[string]string)

		for _, p := range pairs {
			k := strings.ToLower(p.Name)
			if (k == "netflixid" || k == "netflix_id") && currentMap["netflixid"] != "" {
				if cs := cookieMapToSet(currentMap); cs != nil {
					sets = append(sets, cs)
				}
				currentMap = make(map[string]string)
			}
			currentMap[p.Name] = p.Value
		}
		if cs := cookieMapToSet(currentMap); cs != nil {
			sets = append(sets, cs)
		}
		if len(sets) > 0 {
			return sets, true
		}
	}

	// Case B: array of session objects
	var sessions []map[string]interface{}
	if err := json.Unmarshal(data, &sessions); err == nil && len(sessions) > 0 {
		var out []*models.CookieSet
		for _, s := range sessions {
			if cs := buildFromMap(s); cs != nil {
				out = append(out, cs)
			}
		}
		if len(out) > 0 {
			return out, true
		}
	}

	return nil, false
}

func trySingleJSON(data []byte) (*models.CookieSet, bool) {
	if !bytes.HasPrefix(data, []byte("{")) {
		return nil, false
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, false
	}
	cs := buildFromMap(obj)
	return cs, cs != nil
}

func buildFromMap(m map[string]interface{}) *models.CookieSet {
	strMap := make(map[string]string)
	for k, v := range m {
		strMap[k] = fmt.Sprintf("%v", v)
	}
	return cookieMapToSet(strMap)
}

func cookieMapToSet(m map[string]string) *models.CookieSet {
	cs := &models.CookieSet{}
	for k, v := range m {
		k2 := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(k, "-", ""), "_", ""))
		switch k2 {
		case "netflixid":
			cs.NetflixId = strings.Trim(v, `"' `)
		case "securenetflixid":
			cs.SecureNetflixId = strings.Trim(v, `"' `)
		case "nfvdid":
			cs.NfvdId = strings.Trim(v, `"' `)
		case "optanonconsent":
			cs.OptanonConsent = strings.Trim(v, `"' `)
		case "cookieexpires", "expires":
			var i int64
			fmt.Sscanf(strings.Trim(v, `"' `), "%d", &i)
			cs.CookieExpires = i
		}
	}
	if cs.NetflixId == "" {
		return nil
	}
	fingerprint(cs)
	return cs
}

// tryNetscape parses single or multi-session Netscape cookie format.
func tryNetscape(data []byte) []*models.CookieSet {
	var sets []*models.CookieSet
	currentMap := make(map[string]string)
	var currentExpires int64

	scanner := newLineScanner(bytes.NewReader(data))
	hasNetflixId := false
	for scanner.Scan() {
		line, ok := cookieLine(scanner.Text())
		if !ok {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			parts = strings.Fields(line)
			if len(parts) < 2 {
				continue
			}
		}

		var name, value string
		switch {
		case len(parts) >= 7:
			// domain, flag, path, secure, expiry, name, value
			name, value = parts[5], strings.Join(parts[6:], "\t")
		case len(parts) == 6:
			// value, domain, path, expiry, name, value-less export
			name, value = parts[4], parts[5]
		default:
			// plain "name<TAB>value" pairs
			name, value = parts[0], strings.Join(parts[1:], "\t")
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" || value == "" {
			continue
		}

		// A new NetflixId starts a new session whatever case the export used:
		// a lower-cased "netflixid" used to keep overwriting the same slot, so
		// a whole file produced one cookie instead of all of them.
		if strings.EqualFold(name, "NetflixId") && hasNetflixId {
			if cs := cookieMapToSet(currentMap); cs != nil {
				if currentExpires > 0 {
					cs.CookieExpires = currentExpires
				}
				sets = append(sets, cs)
			}
			currentMap = make(map[string]string)
			currentExpires = 0
			hasNetflixId = false
		}

		currentMap[name] = value
		if strings.EqualFold(name, "NetflixId") {
			hasNetflixId = true
		}
		if strings.EqualFold(name, "NetflixId") && len(parts) >= 5 {
			var expiry int64
			fmt.Sscanf(strings.TrimSpace(parts[len(parts)-3]), "%d", &expiry)
			currentExpires = expiry
		}
	}

	if len(currentMap) > 0 {
		if cs := cookieMapToSet(currentMap); cs != nil {
			if currentExpires > 0 {
				cs.CookieExpires = currentExpires
			}
			sets = append(sets, cs)
		}
	}

	return sets
}

// tryMultiLineRaw handles text files with multiple cookies (one per line,
// semicolon-delimited cookie strings, or raw ct%3D tokens).
func tryMultiLineRaw(data []byte) []*models.CookieSet {
	var sets []*models.CookieSet
	scanner := newLineScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line, ok := cookieLine(scanner.Text())
		if !ok {
			continue
		}

		// Line format A: Semicolon-delimited cookies e.g. NetflixId=...; SecureNetflixId=...
		if strings.Contains(line, "NetflixId=") {
			m := parseCookieString(line)
			if cs := cookieMapToSet(m); cs != nil {
				sets = append(sets, cs)
				continue
			}
		}

		// Line format B: Raw NetflixId token starting with ct%3D or ct=
		if strings.HasPrefix(line, "ct%3D") || strings.HasPrefix(line, "ct=") {
			cs := &models.CookieSet{NetflixId: line}
			fingerprint(cs)
			sets = append(sets, cs)
			continue
		}

		// Line format C: key=value
		if idx := strings.IndexByte(line, '='); idx > 0 {
			k := strings.TrimSpace(line[:idx])
			v := strings.TrimSpace(line[idx+1:])
			if strings.EqualFold(k, "NetflixId") || strings.EqualFold(k, "netflix_id") {
				cs := &models.CookieSet{NetflixId: v}
				fingerprint(cs)
				sets = append(sets, cs)
			}
		}
	}

	return sets
}

func parseCookieString(s string) map[string]string {
	m := make(map[string]string)
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if idx := strings.IndexByte(part, '='); idx > 0 {
			k := strings.TrimSpace(part[:idx])
			v := strings.TrimSpace(part[idx+1:])
			m[k] = v
		}
	}
	return m
}

func fingerprint(cs *models.CookieSet) {
	raw := cs.NetflixId
	if dec, err := url.QueryUnescape(raw); err == nil {
		raw = dec
	}
	sum := sha256.Sum256([]byte(raw))
	cs.Fingerprint = fmt.Sprintf("%x", sum)
}
