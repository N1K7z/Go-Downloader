<div align="center">

<br/>

<img src="logo.png" width="90" alt="Go-Downloader" style="border-radius:50%" />

<br/><br/>

# Go-Downloader

Self-hosted video downloader — Go + yt-dlp

</div>

---

## About

Go-Downloader adalah Web-based video downloader "buatan lokal indonesia" yang bisa jalan di server sendiri. Support YouTube, Instagram, Pinterest, dan platform lainnya via yt-dlp. Output MP4, MP3 (foto/thumnail sedang proses tahap perkembangan)

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
sudo apt install yt-dlp
sudo apt install ffmpeg
sudo apt install chromium
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
