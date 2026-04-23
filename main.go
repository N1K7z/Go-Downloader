package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

var (
	ipsMu       sync.Mutex
	ips         = make(map[string]*rate.Limiter)
	downloadSem = make(chan struct{}, 3)
)

func getLimiter(ip string) *rate.Limiter {
	ipsMu.Lock()
	defer ipsMu.Unlock()
	limiter, exists := ips[ip]
	if !exists {
		limiter = rate.NewLimiter(rate.Every(5*time.Second), 3)
		ips[ip] = limiter
	}
	return limiter
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
	host = strings.ToLower(host)
	host = strings.TrimPrefix(host, "www.")
	allowed := []string{
		"youtube.com", "youtu.be", "twitter.com", "x.com",
		"tiktok.com", "instagram.com", "pinterest.com", "pin.it",
		"facebook.com", "fb.watch", "vimeo.com",
	}
	for _, a := range allowed {
		if host == a || strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
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

func securityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip, _, _ := net.SplitHostPort(c.Request.RemoteAddr)
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
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return strings.TrimSpace(outBuf.String()), strings.TrimSpace(errBuf.String()), err
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.File("./index.html")
	})

	r.GET("/metadata", securityMiddleware(), func(c *gin.Context) {
		targetURL := normalizeURL(c.Query("url"))

		u, err := url.ParseRequestURI(targetURL)
		if err != nil || !isAllowedHost(u.Host) {
			c.JSON(400, gin.H{"error": "URL tidak valid atau domain tidak didukung."})
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()

		args := []string{
			"--no-playlist",
			"--get-title",
			"--get-duration",
			"--get-id",
			targetURL,
		}

		title, stderr, err := runYtdlp(ctx, args)
		if err != nil {
			c.JSON(500, gin.H{"error": "Gagal mendapatkan metadata.", "detail": stderr})
			return
		}

		c.JSON(200, gin.H{
			"title":    title,
			"details":  fmt.Sprintf("ID: %s", strings.Split(title, "\n")[1]),
			"duration": strings.Split(title, "\n")[2],
		})
	})

	r.GET("/dl", securityMiddleware(), func(c *gin.Context) {
		targetURL := normalizeURL(c.Query("url"))
		isAudio := c.Query("format") == "mp3"
		res := c.Query("res")
		if res == "" {
			res = "720"
		}

		u, err := url.ParseRequestURI(targetURL)
		if err != nil || !isAllowedHost(u.Host) {
			c.JSON(400, gin.H{"error": "URL tidak valid atau domain tidak didukung."})
			return
		}

		select {
		case downloadSem <- struct{}{}:
			defer func() { <-downloadSem }()
		default:
			c.JSON(503, gin.H{"error": "Server sibuk (max 3 download), coba lagi nanti."})
			return
		}

		tmpID := fmt.Sprintf("dl-%d", time.Now().UnixNano())
		tmpTmpl := fmt.Sprintf("/tmp/%s.%%(ext)s", tmpID)

		defer func() {
			go func() {
				time.Sleep(30 * time.Second)
				matches, _ := filepath.Glob(fmt.Sprintf("/tmp/%s*", tmpID))
				for _, f := range matches {
					os.Remove(f)
				}
			}()
		}()

		ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Minute)
		defer cancel()

		host := strings.ToLower(u.Host)
		host = strings.TrimPrefix(host, "www.")
		isPinterest := strings.Contains(host, "pinterest") || strings.Contains(host, "pin.it")

		baseArgs := []string{
			"--no-playlist",
			"-o", tmpTmpl,
			"--socket-timeout", "30",
			"--http-chunk-size", "10M",
			"--retries", "3",
			"--fragment-retries", "3",
			"--no-warnings",
			"--user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		}

		if strings.Contains(host, "instagram.com") {
			baseArgs = append(baseArgs, "--no-check-certificate")
		}

		if _, err := os.Stat("cookies.txt"); err == nil {
			baseArgs = append(baseArgs, "--cookies", "cookies.txt")
		}

		var lastErrMsg string
		success := false

		if isAudio {
			args := append(append([]string{}, baseArgs...), "-x", "--audio-format", "mp3", "--audio-quality", "0", targetURL)
			_, stderr, err := runYtdlp(ctx, args)
			if err != nil {
				log.Printf("[AUDIO] FAIL - %s", stderr)
				c.JSON(500, gin.H{"error": "Gagal download audio.", "detail": stderr})
				return
			}
			success = true
		} else {
			var formatFallbacks []string
			if isPinterest {
				formatFallbacks = []string{
					"best",
					"bestvideo+bestaudio/best",
					"worst",
				}
			} else {
				formatFallbacks = []string{
					fmt.Sprintf("bestvideo[height<=%s]+bestaudio/best[height<=%s]/best", res, res),
					"best",
					"bestvideo+bestaudio/best",
					"worst",
				}
			}

			for _, tryFmt := range formatFallbacks {
				args := append(append([]string{}, baseArgs...), "-f", tryFmt)
				if !isPinterest {
					args = append(args, "--merge-output-format", "mp4")
				} else {
					args = append(args, "--add-header", "Referer: https://www.pinterest.com")
					args = append(args, "--downloader", "ffmpeg")
				}
				args = append(args, targetURL)

				log.Printf("Trying format: %s", tryFmt)
				_, stderr, err := runYtdlp(ctx, args)
				if err != nil {
					lastErrMsg = stderr
					log.Printf("Format %s gagal: %s", tryFmt, stderr)
					continue
				}
				log.Printf("Format %s berhasil", tryFmt)
				success = true
				break
			}
		}

		if !success {
			c.JSON(500, gin.H{"error": "Gagal download.", "detail": lastErrMsg})
			return
		}

		matches, _ := filepath.Glob(fmt.Sprintf("/tmp/%s.*", tmpID))
		var finalFile string
		for _, m := range matches {
			if !strings.HasSuffix(m, ".part") && !strings.HasSuffix(m, ".ytdl") && !strings.HasSuffix(m, ".tmp") {
				finalFile = m
				break
			}
		}

		if finalFile == "" {
			log.Printf("File tidak ditemukan di /tmp/%s.*", tmpID)
			c.JSON(500, gin.H{"error": "File tidak ditemukan setelah proses."})
			return
		}

		log.Printf("Serving: %s", finalFile)
		baseName := filepath.Base(finalFile)
		ext := filepath.Ext(baseName)
		title := sanitizeTitle(strings.TrimSuffix(baseName, ext))

		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s%s"`, title, ext))
		c.File(finalFile)
	})

	log.Println("🚀 GoDownloader RUNNING ON :8080")
	r.Run(":8080")
}