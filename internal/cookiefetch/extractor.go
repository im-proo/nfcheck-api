// Package cookiefetch provides a multi-format cookie extractor.
// Supports: .txt (Netscape/JSON/raw/multi-line), .json, .zip, .rar archives (nested).
package cookiefetch

import (
	"archive/zip"
	"bufio"
	"bytes"
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
	maxZipFiles            = 50000
	maxZipFileSize         = 64 * 1024 * 1024  // 64MB per file
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

	// 1. Try JSON Array of cookies or sessions
	if sets, ok := tryJSONArray(trimmed); ok && len(sets) > 0 {
		return sets, nil
	}

	// 2. Try single JSON object
	if cs, ok := trySingleJSON(trimmed); ok {
		return []*models.CookieSet{cs}, nil
	}

	// 3. Try Netscape format
	if sets := tryNetscape(trimmed); len(sets) > 0 {
		return sets, nil
	}

	// 4. Try multi-line raw cookies / strings
	return tryMultiLineRaw(trimmed), nil
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

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 7 {
			// Try space-delimited
			parts = strings.Fields(line)
			if len(parts) < 7 {
				continue
			}
		}

		name := parts[5]
		value := parts[6]

		if name == "NetflixId" && currentMap["NetflixId"] != "" {
			if cs := cookieMapToSet(currentMap); cs != nil {
				if currentExpires > 0 {
					cs.CookieExpires = currentExpires
				}
				sets = append(sets, cs)
			}
			currentMap = make(map[string]string)
			currentExpires = 0
		}

		currentMap[name] = value
		if name == "NetflixId" {
			fmt.Sscanf(parts[4], "%d", &currentExpires)
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
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
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
