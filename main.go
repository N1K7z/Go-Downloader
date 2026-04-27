package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

const (
	maxCommandLogBytes = 64 * 1024
	maxResHeight       = 2160
	minResHeight       = 144
)

type visitorLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.max <= 0 {
		return len(p), nil
	}
	if len(p) >= b.max {
		b.buf.Reset()
		_, _ = b.buf.Write(p[len(p)-b.max:])
		return len(p), nil
	}
	overflow := b.buf.Len() + len(p) - b.max
	if overflow > 0 {
		current := b.buf.Bytes()
		b.buf.Reset()
		_, _ = b.buf.Write(current[overflow:])
	}
	_, _ = b.buf.Write(p)
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	return strings.TrimSpace(b.buf.String())
}

var (
	ipsMu       sync.Mutex
	ips         = make(map[string]*visitorLimiter)
	downloadSem = make(chan struct{}, 3)
)

func getLimiter(ip string) *rate.Limiter {
	ipsMu.Lock()
	defer ipsMu.Unlock()
	now := time.Now()
	info, exists := ips[ip]
	if !exists {
		info = &visitorLimiter{
			limiter:  rate.NewLimiter(rate.Every(5*time.Second), 3),
			lastSeen: now,
		}
		ips[ip] = info
	}
	info.lastSeen = now
	return info.limiter
}

func cleanupLimiters(maxIdle time.Duration) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-maxIdle)
		ipsMu.Lock()
		for ip, info := range ips {
			if info.lastSeen.Before(cutoff) {
				delete(ips, ip)
			}
		}
		ipsMu.Unlock()
	}
}

func normalizeURL(inputURL string) string {
	inputURL = strings.TrimSpace(inputURL)
	if strings.Contains(inputURL, "youtube.com/shorts/") {
		parts := strings.Split(inputURL, "/shorts/")
		if len(parts) > 1 {
			videoID := strings.Split(parts[1], "?")[0]
			return fmt.Sprintf("https://www.youtube.com/watch?v=%s", videoID)
		}
	}
	return inputURL
}

func isAllowedHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(host, ".local") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			return false
		}
	}
	return true
}

func sanitizeTitle(title string) string {
	if title == "" {
		return "video_download"
	}
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(`<>:"/\|?*`, r) {
			return -1
		}
		return r
	}, title)
}

func parseResolution(input string) string {
	if input == "" {
		return "720"
	}
	v := 0
	for _, r := range input {
		if r < '0' || r > '9' {
			return "720"
		}
		v = v*10 + int(r-'0')
	}
	if v < minResHeight {
		v = minResHeight
	}
	if v > maxResHeight {
		v = maxResHeight
	}
	return fmt.Sprintf("%d", v)
}

func listCompletedFiles(tmpDir string) ([]string, error) {
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		return nil, err
	}
	var matches []string
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		name := file.Name()
		if strings.HasSuffix(name, ".part") || strings.HasSuffix(name, ".ytdl") || strings.HasSuffix(name, ".tmp") {
			continue
		}
		matches = append(matches, filepath.Join(tmpDir, name))
	}
	return matches, nil
}

func firstCompletedFile(tmpDir string) string {
	files, err := listCompletedFiles(tmpDir)
	if err != nil || len(files) == 0 {
		return ""
	}
	return files[0]
}

func clientIP(remoteAddr string) string {
	if remoteAddr == "" {
		return "unknown"
	}
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && ip != "" {
		return ip
	}
	if parsed := net.ParseIP(remoteAddr); parsed != nil {
		return remoteAddr
	}
	return "unknown"
}

func securityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := clientIP(c.Request.RemoteAddr)
		if !getLimiter(ip).Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Sabar bro, jangan ngebut-ngebut!"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func runYtdlp(ctx context.Context, args []string) (string, string, error) {
	cmd := exec.CommandContext(ctx, "yt-dlp", args...)
	outBuf := &limitedBuffer{max: maxCommandLogBytes}
	errBuf := &limitedBuffer{max: maxCommandLogBytes}
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf
	err := cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

func streamYtdlp(c *gin.Context, ctx context.Context, args []string, fileName string, contentType string) error {
	cmd := exec.CommandContext(ctx, "yt-dlp", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	errBuf := &limitedBuffer{max: maxCommandLogBytes}
	cmd.Stderr = errBuf
	if err := cmd.Start(); err != nil {
		return err
	}

	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, sanitizeTitle(fileName)))
	c.Header("Content-Type", contentType)
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)

	if _, err := io.Copy(c.Writer, stdout); err != nil {
		_ = cmd.Wait()
		return err
	}
	if err := cmd.Wait(); err != nil {
		if msg := errBuf.String(); msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}

func formatDuration(seconds int) string {
	if seconds <= 0 {
		return "0:00"
	}
	if seconds < 3600 {
		return fmt.Sprintf("%d:%02d", seconds/60, seconds%60)
	}
	h := seconds / 3600
	m := (seconds % 3600) / 60
	s := seconds % 60
	return fmt.Sprintf("%d:%02d:%02d", h, m, s)
}

type ytdlpMeta struct {
	Title    string `json:"title"`
	Uploader string `json:"uploader"`
	Duration int    `json:"duration"`
}

type ytdlpPhotoInfo struct {
	Thumbnail  string `json:"thumbnail"`
	Thumbnails []struct {
		URL string `json:"url"`
	} `json:"thumbnails"`
}

func fetchMetadata(ctx context.Context, targetURL string) (ytdlpMeta, string, error) {
	args := []string{
		"--no-playlist",
		"--skip-download",
		"--user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"--print", "%(title)s",
		"--print", "%(uploader)s",
		"--print", "%(duration)s",
		targetURL,
	}
	if _, err := os.Stat("cookies.txt"); err == nil {
		args = append([]string{"--cookies", "cookies.txt"}, args...)
	}
	out, stderr, err := runYtdlp(ctx, args)
	if err != nil {
		return ytdlpMeta{}, stderr, err
	}
	lines := strings.Split(out, "\n")
	if len(lines) < 3 {
		return ytdlpMeta{}, stderr, fmt.Errorf("metadata output incomplete")
	}

	durationRaw := strings.TrimSpace(lines[2])
	var duration int
	_, scanErr := fmt.Sscanf(durationRaw, "%d", &duration)
	if scanErr != nil {
		duration = 0
	}

	meta := ytdlpMeta{
		Title:    strings.TrimSpace(lines[0]),
		Uploader: strings.TrimSpace(lines[1]),
		Duration: duration,
	}
	return meta, stderr, nil
}

func fileNameFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "video_download"
	}
	host := strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
	if host == "" {
		host = "video"
	}
	pathPart := strings.Trim(strings.ReplaceAll(u.Path, "/", "_"), "_")
	if pathPart == "" {
		pathPart = strconv.FormatInt(time.Now().Unix(), 10)
	}
	return sanitizeTitle(host + "_" + pathPart)
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	go cleanupLimiters(1 * time.Hour)

	r.GET("/", func(c *gin.Context) {
		c.File("./index.html")
	})

	r.GET("/metadata", securityMiddleware(), func(c *gin.Context) {
		targetURL := normalizeURL(c.Query("url"))
		u, err := url.ParseRequestURI(targetURL)
		if err != nil || !isAllowedHost(u.Hostname()) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "URL tidak valid atau domain tidak didukung."})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()
		meta, stderr, err := fetchMetadata(ctx, targetURL)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mendapatkan metadata.", "detail": strings.TrimSpace(stderr)})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"title":    meta.Title,
			"details":  meta.Uploader,
			"duration": formatDuration(meta.Duration),
		})
	})

	r.GET("/dl", securityMiddleware(), func(c *gin.Context) {
		targetURL := normalizeURL(c.Query("url"))
		format := c.Query("format")
		res := parseResolution(c.Query("res"))

		u, err := url.ParseRequestURI(targetURL)
		if err != nil || !isAllowedHost(u.Hostname()) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "URL tidak valid atau domain tidak didukung."})
			return
		}

		select {
		case downloadSem <- struct{}{}:
			defer func() { <-downloadSem }()
		default:
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Server sibuk (max 3 download), coba lagi nanti."})
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Minute)
		defer cancel()

		host := strings.ToLower(strings.TrimPrefix(u.Hostname(), "www."))
		isPinterest := strings.Contains(host, "pinterest") || strings.Contains(host, "pin.it")

		if format == "mp4" || format == "" {
			tmpID := fmt.Sprintf("dl-video-%d", time.Now().UnixNano())
			tmpDir := filepath.Join(os.TempDir(), tmpID)
			if err := os.MkdirAll(tmpDir, 0o755); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create temp folder."})
				return
			}
			defer os.RemoveAll(tmpDir)

			baseArgs := []string{
				"--no-warnings",
				"--socket-timeout", "30",
				"--retries", "3",
				"--fragment-retries", "3",
				"--hls-use-mpegts",
				"--user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
				"--merge-output-format", "mp4",
				"-o", fmt.Sprintf("%s/%%(title)s.%%(ext)s", tmpDir),
			}
			if isPinterest {
				baseArgs = append(baseArgs, "--add-header", "Referer: https://www.pinterest.com")
			}
			if _, err := os.Stat("cookies.txt"); err == nil {
				baseArgs = append([]string{"--cookies", "cookies.txt"}, baseArgs...)
			}

			formatFallbacks := []string{
				fmt.Sprintf("bv*[height<=%s]+ba/b[height<=%s]/best[height<=%s]", res, res, res),
				"bv*+ba/best",
				"best",
				"",
			}
			var lastErr string
			success := false
			for _, tryFmt := range formatFallbacks {
				args := append([]string{}, baseArgs...)
				if tryFmt != "" {
					args = append(args, "-f", tryFmt)
				}
				args = append(args, "-S", "res,fps,vcodec,acodec", targetURL)
				_, stderr, err := runYtdlp(ctx, args)
				if err != nil {
					lastErr = stderr
					continue
				}
				success = true
				break
			}
			if !success {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal download video.", "detail": lastErr})
				return
			}

			finalFile := firstCompletedFile(tmpDir)
			if finalFile == "" {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "File tidak ditemukan setelah proses."})
				return
			}
			ext := filepath.Ext(finalFile)
			title := sanitizeTitle(strings.TrimSuffix(filepath.Base(finalFile), ext))
			c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s%s"`, title, ext))
			c.File(finalFile)
			return
		}

		tmpID := fmt.Sprintf("dl-%d", time.Now().UnixNano())
		tmpDir := filepath.Join(os.TempDir(), tmpID)
		if err := os.MkdirAll(tmpDir, 0o755); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create temp folder."})
			return
		}
		defer os.RemoveAll(tmpDir)

		baseArgs := []string{
			"--no-warnings",
			"--socket-timeout", "30",
			"--http-chunk-size", "10M",
			"--retries", "3",
			"--fragment-retries", "3",
			"--user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"--restrict-filenames",
			"-o", fmt.Sprintf("%s/%%(title)s.%%(ext)s", tmpDir),
		}
		if strings.Contains(host, "instagram.com") {
			baseArgs = append(baseArgs, "--no-check-certificate")
		}
		if _, err := os.Stat("cookies.txt"); err == nil {
			baseArgs = append(baseArgs, "--cookies", "cookies.txt")
		}

		var finalFile string

		if format == "photo" {
			out, stderr, err := runYtdlp(ctx, []string{"--no-playlist", "--skip-download", "--print-json", targetURL})
			if err != nil {
				log.Printf("[PHOTO] yt-dlp JSON fetch failed: %s", stderr)
				fallbackArgs := append([]string{}, baseArgs...)
				fallbackArgs = append(fallbackArgs, "-f", "best", targetURL)
				_, stderr, err = runYtdlp(ctx, fallbackArgs)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal download foto.", "detail": stderr})
					return
				}
				finalFile = firstCompletedFile(tmpDir)
			} else {
				var info ytdlpPhotoInfo
				if err := json.Unmarshal([]byte(out), &info); err != nil {
					log.Printf("[PHOTO] JSON parse error: %v", err)
				} else {
					var imgURL string
					if info.Thumbnail != "" {
						imgURL = info.Thumbnail
					} else if len(info.Thumbnails) > 0 {
						imgURL = info.Thumbnails[0].URL
					}
					if imgURL != "" {
						req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, imgURL, nil)
						if reqErr == nil {
							resp, dlErr := http.DefaultClient.Do(req)
							if dlErr == nil {
								defer resp.Body.Close()
								if resp.StatusCode == http.StatusOK {
									imgName := filepath.Base(imgURL)
									if idx := strings.Index(imgName, "?"); idx != -1 {
										imgName = imgName[:idx]
									}
									if imgName == "" || !strings.Contains(imgName, ".") {
										imgName = "image.jpg"
									}
									destPath := filepath.Join(tmpDir, imgName)
									f, createErr := os.Create(destPath)
									if createErr == nil {
										_, copyErr := io.Copy(f, resp.Body)
										_ = f.Close()
										if copyErr == nil {
											finalFile = destPath
										}
									}
								}
							}
						}
					}
				}
				if finalFile == "" {
					fallbackArgs := append([]string{}, baseArgs...)
					fallbackArgs = append(fallbackArgs, "-f", "best", targetURL)
					_, stderr, err = runYtdlp(ctx, fallbackArgs)
					if err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal download foto.", "detail": stderr})
						return
					}
					finalFile = firstCompletedFile(tmpDir)
				}
			}

			if finalFile == "" {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "File tidak ditemukan setelah proses."})
				return
			}
			ext := filepath.Ext(finalFile)
			title := sanitizeTitle(strings.TrimSuffix(filepath.Base(finalFile), ext))
			c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s%s"`, title, ext))
			c.File(finalFile)
			return
		}

		if format == "mp3" {
			args := append([]string{}, baseArgs...)
			args = append(args, "-x", "--audio-format", "mp3", "--audio-quality", "0", targetURL)
			_, stderr, err := runYtdlp(ctx, args)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal download audio.", "detail": stderr})
				return
			}

			matches, err := listCompletedFiles(tmpDir)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to inspect downloaded files.", "detail": err.Error()})
				return
			}
			for _, m := range matches {
				if strings.EqualFold(filepath.Ext(m), ".mp3") {
					finalFile = m
					break
				}
			}
			if finalFile == "" {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Audio file not found after download."})
				return
			}
			ext := filepath.Ext(finalFile)
			title := sanitizeTitle(strings.TrimSuffix(filepath.Base(finalFile), ext))
			c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s%s"`, title, ext))
			c.File(finalFile)
			return
		}

		var formatFallbacks []string
		if isPinterest {
			formatFallbacks = []string{"best", "bestvideo+bestaudio/best", "worst"}
		} else {
			formatFallbacks = []string{
				fmt.Sprintf("bestvideo[height<=%s]+bestaudio/best[height<=%s]/best", res, res),
				"best",
				"bestvideo+bestaudio/best",
				"worst",
			}
		}

		var lastErrMsg string
		success := false
		for _, tryFmt := range formatFallbacks {
			args := append([]string{}, baseArgs...)
			args = append(args, "-f", tryFmt)
			if !isPinterest {
				args = append(args, "--merge-output-format", "mp4")
			} else {
				args = append(args, "--add-header", "Referer: https://www.pinterest.com", "--downloader", "ffmpeg")
			}
			args = append(args, targetURL)

			_, stderr, err := runYtdlp(ctx, args)
			if err != nil {
				lastErrMsg = stderr
				continue
			}
			success = true
			break
		}
		if !success {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal download.", "detail": lastErrMsg})
			return
		}

		finalFile = firstCompletedFile(tmpDir)
		if finalFile == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "File tidak ditemukan setelah proses."})
			return
		}
		ext := filepath.Ext(finalFile)
		title := sanitizeTitle(strings.TrimSuffix(filepath.Base(finalFile), ext))
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s%s"`, title, ext))
		c.File(finalFile)
	})

	log.Println("GoDownloader RUNNING ON :8080")
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server failed: %v", err)
	}
}
