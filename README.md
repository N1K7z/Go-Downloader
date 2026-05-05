<div align="center">

<img src="logo.png" width="100" alt="Go-Downloader" />

# Go-Downloader

![Version](https://img.shields.io/badge/version-0.2-blue?style=flat-square)
![Go](https://img.shields.io/badge/Go-1.26.2--X-00ADD8?style=flat-square&logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-Non--Commercial-cc1111?style=flat-square)

<img src="https://github.githubassets.com/images/mona-loading-dark.gif" width="60" alt="loading" />

</div>

---

## About

> Go-Downloader is an open-source, web-based video downloader designed to run on your own server.  
> Support YouTube, Instagram, Pinterest, and various other platforms via yt-dlp.  
> Output: MP4 & MP3.

> Go-Downloader adalah project Open Source web-based video downloader yang bisa jalan di server sendiri.  
> Support YouTube, Instagram, Pinterest, dan platform lainnya via yt-dlp.  
> Output: MP4, MP3.

---

## Screenshots

<div align="center">
<table>
  <tr>
    <td><img src="screenshots/1.png" width="180" /></td>
    <td><img src="screenshots/2.png" width="180" /></td>
    <td><img src="screenshots/3.png" width="180" /></td>
    <td><img src="screenshots/4.png" width="180" /></td>
  </tr>
</table>
</div>

---

## Installation

### Prerequisites
```bash
sudo apt install yt-dlp ffmpeg chromium
```

### Run
```bash
git clone https://github.com/N1K7z/Go-Downloader.git
cd Go-Downloader
go mod tidy
go run main.go
```

Buka **http://localhost:8080**

### Build binary
```bash
go build -o go-downloader .
./go-downloader
```

### Cookie support (opsional)
```bash
cp /path/to/cookies.txt ./cookies.txt
```
