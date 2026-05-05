<div align="center">

<br/>

<img src="logo.png" width="90" alt="Go-Downloader" style="border-radius:50%" />

<br/><br/>

# Go-Downloader

Self-hosted video downloader — Go + yt-dlp

</div>

---

## About

Web-based video downloader yang bisa jalan di server sendiri. Support YouTube, Instagram, Pinterest, dan platform lainnya via yt-dlp. Output bisa MP4, MP3, atau foto langsung.

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
pip install yt-dlp
sudo apt install ffmpeg
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
